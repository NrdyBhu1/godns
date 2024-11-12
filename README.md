# Simple DNS Client in Go

This is a simple DNS client implemented in Go that sends a DNS query to a specified DNS server and prints the response. The client currently supports querying A records.

## Features

- Sends DNS queries to a specified DNS server (default: Google's public DNS server at `8.8.8.8`).
- Supports querying A records for a given domain.
- Parses and displays the DNS response, including the resolved IP address.

## Requirements

- Go 1.16 or later

## Installation

1. Clone the repository:
```bash
$ git clone https://github.com/NrdyBhu1/godns.git
$ cd godns
```
2. Build the application:
```bash
$ go build
```

## Usage

Run the DNS client and enter the domain name you want to query:

```bash
./godns
```

You will be prompted to enter a domain name:

```bash
Enter domain: google.com
```

After entering the domain, the client will send a DNS query and display the response:

```bash
&main.DnsPacket{header:..., answers:...}
192.168.1.1
```
