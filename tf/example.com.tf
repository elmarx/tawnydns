resource "powerdns_zone" "example_com" {
  kind = "Master"
  name = "example.com."
}

resource "powerdns_record" "www_example_com" {
  zone    = powerdns_zone.example_com.name
  name    = "www.example.com."
  type    = "AAAA"
  records = ["::1"]
  ttl     = 300
}