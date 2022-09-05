use rusoto_core::{credential::ProfileProvider, HttpClient, Region};
use rusoto_sns::*;

use crate::configuration;

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
    pub fn new_local_client(topic_arn: String) -> Self {
        // Use local profile for local development
        let aws_profile = configuration::get_aws_profile();
        let credentials_provider = ProfileProvider::with_default_credentials(aws_profile)
            .expect("Could not create credentials provider for local S3 client");
        let request_dispatcher =
            HttpClient::new().expect("Couldn't initialise request dispatcher for local S3 client");
        let client = SnsClient::new_with(request_dispatcher, credentials_provider, Region::UsEast1);

        Self {
            sns_client: client,
            topic_arn,
        }
    }

    pub fn new(topic_arn: String) -> Self {
        Self {
            sns_client: SnsClient::new(configuration::get_aws_region()),
            topic_arn,
        }
    }

    pub async fn publish_message(&self, message: String) {
        let publish_input = PublishInput {
            message,
            topic_arn: Some(self.topic_arn.clone()),
            ..Default::default()
        };

        match self.sns_client.publish(publish_input).await {
            Ok(_) => println!("Successfully published message to SNS"),
            Err(err) => eprintln!("Failed to publish message to SNS. {}", err),
        }
    }
}
