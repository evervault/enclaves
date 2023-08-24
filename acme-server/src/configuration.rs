pub fn get_acme_s3_bucket() -> String {
    std::env::var("ACME_S3_BUCKET").expect("ACME_S3_BUCKET is not set in env")
}
