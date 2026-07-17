#!/bin/bash
# Targeted for AWS EC2 (Ubuntu 24.04)

# Ensure IP is provided
if [ -z "$1" ]; then
  echo "Usage: ./smoke_test.sh <elastic-ip>"
  exit 1
fi

ELASTIC_IP=$1
API_URL="http://${ELASTIC_IP}:8080/api"

# Temporary variables
EMAIL="testuser_$(date +%s)@example.com"
PASSWORD="strongpassword123"
DEVICE_ID="smoke-test-device"
PUB_KEY="aBCdEFgHijKlmnoPqrStUvWxyz0123456789abcdeF="

echo "========================================="
echo " Scale VPN Remote Smoke Test "
echo " Testing against: $ELASTIC_IP"
echo "========================================="

echo -e "\n1. Registering User ($EMAIL)..."
HTTP_CODE=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$API_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")

cat /tmp/resp.json | jq .
if [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "200" ]; then
    echo "Error: Registration failed with HTTP $HTTP_CODE"
    exit 1
fi

echo -e "\n2. Logging In..."
HTTP_CODE=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$API_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")

cat /tmp/resp.json | jq .
if [ "$HTTP_CODE" != "200" ]; then
    echo "Error: Login failed with HTTP $HTTP_CODE"
    exit 1
fi

JWT=$(cat /tmp/resp.json | jq -r '.token')
if [ "$JWT" == "null" ] || [ -z "$JWT" ]; then
    echo "Login failed. No JWT received."
    exit 1
fi

echo -e "\n3. Registering Device..."
HTTP_CODE=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$API_URL/devices/register" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d "{\"device_id\":\"$DEVICE_ID\", \"public_key\":\"$PUB_KEY\"}")

cat /tmp/resp.json | jq .
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
    echo "Error: Device registration failed with HTTP $HTTP_CODE"
    exit 1
fi

echo -e "\n4. Sending Device Heartbeat..."
HTTP_CODE=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$API_URL/devices/heartbeat" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Device-Public-Key: $PUB_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"device_id\":\"$DEVICE_ID\", \"endpoint\":\"203.0.113.1:51820\", \"local_endpoint\":\"192.168.1.10:51820\"}")

cat /tmp/resp.json | jq .
if [ "$HTTP_CODE" != "200" ]; then
    echo "Error: Heartbeat failed with HTTP $HTTP_CODE"
    exit 1
fi

echo -e "\n5. Polling Devices (/api/poll)..."
HTTP_CODE=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X GET "$API_URL/poll" \
  -H "Authorization: Bearer $JWT")

cat /tmp/resp.json | jq .
if [ "$HTTP_CODE" != "200" ]; then
    echo "Error: Poll failed with HTTP $HTTP_CODE"
    exit 1
fi

echo -e "\n6. Checking Relay Server (Testing TCP connect on 8443)..."
if nc -z -v -w5 $ELASTIC_IP 8443 2>&1 | grep -q 'succeeded\|open'; then
    echo "Relay Server is listening on port 8443!"
else
    echo "Relay Server port 8443 is unreachable."
fi

echo -e "\nSmoke test completed successfully!"
