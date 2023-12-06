FROM rust:latest as build

# create a new empty shell project
RUN rustup default nightly-gnu

RUN USER=root cargo new --bin owo69
WORKDIR /owo69

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/narqyez_handler*
RUN cargo build --release

# our final base
FROM archlinux:latest

# copy the build artifact from the build stage
COPY --from=build /owo69/target/release/owo69 ./

# set the startup command to run your binary
CMD ["./owo69"]
