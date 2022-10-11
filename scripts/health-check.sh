rm -f health-check-response.txt
# this writes the response to the request to a file, and stores the status code as a variable
response_code=$(curl -s -o health-check-response.txt -w "%{http_code}" -H 'User-Agent: ECS-HealthCheck' localhost:3032)

# curl will set the response code to 000 if the request errors
if [ $response_code == "000" ]; then
    echo "Health check failed. Failed to connect to control plane."
    exit 1
elif [ $response_code != "200" ]; then
    response=$(cat health-check-response.txt)
    echo "Health check failed. Response from control-plane: $response"
    exit 1
fi