output "server_ip" {
  value = aws_instance.server.public_ip
}

output "client_ip" {
  value = aws_instance.client.public_ip
}

output "server_instance_type" {
  value = aws_instance.server.instance_type
}

output "client_instance_type" {
  value = aws_instance.client.instance_type
}

# Ligne a copier dans deploy/hosts.env (lu par scripts/campaign.sh).
output "hosts_env" {
  value = <<-EOT
    SERVER=ubuntu@${aws_instance.server.public_ip}
    CLIENT=ubuntu@${aws_instance.client.public_ip}
  EOT
}
