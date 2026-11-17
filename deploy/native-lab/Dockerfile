# Dedicated analysis image; build and deploy by digest in the lab profile.
FROM public.ecr.aws/docker/library/debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY ptrace_probe.c /tmp/artex-ptrace-probe.c
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gdb=13.1-3 binutils=2.40-2 gcc=4:12.2.0-3 libc6=2.36-9+deb12u14 libc6-dev=2.36-9+deb12u14 \
      python3=3.11.2-1+b1 \
 && rm -rf /var/lib/apt/lists/*
RUN gcc -O0 -g -fno-pie -no-pie /tmp/artex-ptrace-probe.c -o /usr/local/bin/artex-ptrace-probe
WORKDIR /work
RUN mkdir -p /work/deps /work/loader && chmod 0555 /work /work/deps /work/loader
USER 65534
ENTRYPOINT ["/bin/false"]
