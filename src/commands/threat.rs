pub async fn run(id: &str, human: bool) -> Result<(), String> {
    super::issue::run(id, true, human).await
}
