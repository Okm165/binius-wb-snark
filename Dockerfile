# Use an official Rust base image with Node.js installed
FROM rust:latest

# Install Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean

# Install Clang and other build tools
RUN apt-get update && apt-get install -y \
    clang \
    build-essential \
    libssl-dev \
    && apt-get clean

# Install wasm-pack globally
RUN cargo install wasm-pack

# Set the working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies with fallback
RUN npm cache clean --force && npm config set registry http://registry.npmjs.org/ && npm install

# Copy the rest of the application code
COPY . .

# Build Rust code with wasm-pack
RUN cd backend && \
    wasm-pack build --release --out-dir out --target web && \
    cd out && npm link

# Link the Rust-built package
RUN npm link binius-keccak

# Build the Next.js application
RUN npm run build

# Expose the port the app runs on
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
