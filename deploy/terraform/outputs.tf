output "public_ip" {
  description = "Elastic IP of the CTF host."
  value       = aws_eip.ctf.public_ip
}

output "ctfd_url" {
  description = "CTFd platform — where players sign in and read challenges."
  value       = "http://${aws_eip.ctf.public_ip}/"
}

output "app_gate_url" {
  description = "The vulnerable Danubius Bank app (behind its own gate) — the target players attack."
  value       = "http://${aws_eip.ctf.public_ip}:8080/"
}

output "ssh" {
  description = "SSH command (empty if no key was set)."
  value       = var.ssh_key_name != "" ? "ssh ubuntu@${aws_eip.ctf.public_ip}" : "(SSH disabled: no ssh_key_name)"
}

output "notes" {
  description = "First-boot note."
  value       = "Cloud-init builds images, pulls the LLM model and seeds CTFd - allow ~5-15 min after apply. Watch progress: ssh in and 'tail -f /var/log/danubius-deploy.log'."
}
