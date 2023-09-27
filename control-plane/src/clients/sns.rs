use crate::configuration;
use aws_config::{load_from_env, meta::region::RegionProviderChain};
use aws_sdk_sns::Client as SnsClient;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NotificationMetadata {
    #[serde(rename = "cageUuid")]
    cage_uuid: String,
    #[serde(rename = "cageName")]
    cage_name: String,
    #[serde(rename = "appUuid")]
    app_uuid: String,
}

impl NotificationMetadata {
    pub fn new(cage_uuid: String, cage_name: String, app_uuid: String) -> Self {
        Self {
            cage_uuid,
            cage_name,
            app_uuid,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeregistrationMessage {
    #[serde(rename = "Origin")]
    origin: String,
    #[serde(rename = "NotificationMetadata")]
    notification_metadata: String,
    #[serde(rename = "EC2InstanceId")]
    ec2_instance_id: String,
}

impl DeregistrationMessage {
    pub fn new(
        ec2_instance_id: String,
        cage_uuid: String,
        cage_name: String,
        app_uuid: String,
    ) -> Self {
        Self {
            origin: "ECS".to_string(),
            notification_metadata: serde_json::to_string(&NotificationMetadata::new(
                cage_uuid, cage_name, app_uuid,
            ))
            .unwrap(),
            ec2_instance_id,
        }
    }
}

pub struct ControlPlaneSnsClient {
    sns_client: SnsClient,
    topic_arn: String,
}

impl ControlPlaneSnsClient {
    pub async fn new_local_client(topic_arn: String) -> Self {
        // Use local profile for local development
        let region_provider =
            RegionProviderChain::default_provider().or_else(configuration::get_aws_region());
        let config = aws_config::from_env()
            .profile_name(configuration::get_aws_profile())
            .region(region_provider)
            .load()
            .await;
        let sns_client = SnsClient::new(&config);

        Self {
            sns_client,
            topic_arn,
        }
    }

    pub async fn new(topic_arn: String) -> Self {
        let config = load_from_env().await;
        Self {
            sns_client: SnsClient::new(&config),
            topic_arn,
        }
    }

    pub async fn publish_message(&self, message: String) {
        match self
            .sns_client
            .publish()
            .topic_arn(&self.topic_arn)
            .message(message)
            .send()
            .await
        {
            Ok(_) => log::debug!("Successfully published message to SNS"),
            Err(err) => log::error!("Failed to publish message to SNS. {err}"),
        }
    }
}
