# --- STAGE 1: The Builder (Heavy) ---
# We use the official Rust image to compile the code.
# This stage has all the heavy tools (compiler, cargo, etc.)
FROM rust:1.85 as builder

# Create a new empty shell project
WORKDIR /usr/src/diamond_shield
COPY . .

# Build the release binary (Optimized for speed)
# This creates the executable inside /target/release/
RUN cargo build --release

# --- STAGE 2: The Runtime (Lightweight) ---
# We use a tiny Linux image (Debian Slim) for the final server.
# It has NO compiler, making it much harder for hackers to exploit.
FROM debian:bookworm-slim

# Install OpenSSL (Required for HTTPS/Web requests)
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy ONLY the binary from the "builder" stage
COPY --from=builder /usr/src/diamond_shield/target/release/diamond_shield /usr/local/bin/diamond_shield

# Set the startup command
CMD ["diamond_shield"]
