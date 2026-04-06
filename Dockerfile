# --- Stage 1: Build the executable ---
FROM rust:1.75-bookworm as builder

# Install build dependencies (libpcap-dev for pnet)
RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /usr/src/port-scanner
COPY . .

# Build the project in release mode
RUN cargo build --release

# --- Stage 2: Create the minimal runtime image ---
FROM debian:bookworm-slim

# Install runtime dependencies (libpcap for pnet)
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/port-scanner/target/release/port-scan /app/port-scan

# Copy the public assets for the Web UI
COPY --from=builder /usr/src/port-scanner/public /app/public

# Create scans directory
RUN mkdir /app/scans

# Expose the default Web UI port
EXPOSE 3000

# Run the project
# Note: For SYN scans, you must run the container with --cap-add=NET_ADMIN or --privileged
ENTRYPOINT ["./port-scan"]
CMD ["web"]
