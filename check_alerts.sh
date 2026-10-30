#!/bin/bash
docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log
