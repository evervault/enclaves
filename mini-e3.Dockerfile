FROM rust:1.74-bookworm

ADD target/x86_64-unknown-linux-gnu/release/mini-e3 .

ENTRYPOINT [ "./mini-e3" ]
