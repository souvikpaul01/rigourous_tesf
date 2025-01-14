from kafka import KafkaConsumer

# Define the Kafka topic and server
topic = 'TESF-AID'
bootstrap_servers = '155.54.95.79:31400'

# Create a Kafka consumer
consumer = KafkaConsumer(
    topic,
    bootstrap_servers=bootstrap_servers,
    auto_offset_reset='earliest'
)

# Read and print messages from the topic
for message in consumer:
    print(message.value.decode('utf-8'))


# from kafka import KafkaAdminClient

# admin_client = KafkaAdminClient(bootstrap_servers='155.54.95.79:31400')
# topic_list = admin_client.list_topics()

# print("Topics in the Kafka cluster:")
# for topic in topic_list:
#     print(topic)