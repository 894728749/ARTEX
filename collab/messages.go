package collab

// MessageExchange carries only user-facing text. Tool inputs, results and model
// reasoning never belong to this channel. Sequence numbers survive HTTP retries.
type DeviceMessage struct {
	Seq  int64  `json:"seq"`
	Text string `json:"text"`
}
type Guidance struct {
	ID   int64  `json:"id"`
	Text string `json:"text"`
}
type MessageExchange struct {
	Epoch     int64           `json:"epoch"`
	Messages  []DeviceMessage `json:"messages,omitempty"`
	Delivered []int64         `json:"delivered,omitempty"`
	Seal      bool            `json:"seal,omitempty"`
}
type MessageExchangeReply struct {
	Guidance []Guidance `json:"guidance"`
	Sealed   bool       `json:"sealed"`
}
