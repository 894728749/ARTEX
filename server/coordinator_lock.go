package server

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// The process-level coordinator lock is acquired before NewManager's recovery.
// Pin the connection: a pool Exec would let another session release/lose it.
type CoordinatorLock struct {
	Lost   <-chan struct{}
	cancel context.CancelFunc
	conn   *sql.Conn
	db     *sql.DB
	once   sync.Once
}

func AcquireCoordinatorLock(ctx context.Context, dsn string) (*CoordinatorLock, error) {
	d, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	var acquired bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(7337741021)`).Scan(&acquired); err != nil || !acquired {
		conn.Close()
		d.Close()
		if err != nil {
			return nil, fmt.Errorf("coordinator lock unavailable")
		}
		return nil, fmt.Errorf("another ARTEX coordinator owns this database")
	}
	monitor, cancel := context.WithCancel(ctx)
	lost := make(chan struct{})
	lock := &CoordinatorLock{Lost: lost, cancel: cancel, conn: conn, db: d}
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-monitor.Done():
				return
			case <-ticker.C:
				probe, stop := context.WithTimeout(monitor, 2*time.Second)
				var one int
				err := conn.QueryRowContext(probe, `SELECT 1`).Scan(&one)
				stop()
				if err != nil {
					if monitor.Err() == nil {
						close(lost)
					}
					return
				}
			}
		}
	}()
	return lock, nil
}
func (l *CoordinatorLock) Close() {
	l.once.Do(func() {
		l.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock(7337741021)`)
		l.conn.Close()
		l.db.Close()
	})
}
