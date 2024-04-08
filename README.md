# Implementing a Custom Protocol Using Raw Sockets

## Introduction

This is a custom protocol that works like DNS (but much simpler than DNS) to find out the IP address corresponding to a domain name. The protocol is implemented using raw sockets in C language.

## Compilation and Execution

Execute the following in the root directory of the project in the terminal:

1. For color output, run the following command:
    ```bash
    make all
    ```
2. To run the server, run the following command:
    ```bash
    sudo ./server
    ```
3. To run the client, run the following command:
    ```bash
    sudo ./client <dest_mac>
    ```
4. To clean the executables, run the following command:
    ```bash
    make clean
    ```
5. In case of issues due to color encodings, run the following command:
    ```bash
    make nocolor
    ```

## How to Use

To run commands in the client, run queries in the following format:
```bash
getIP <N> <domain-1> <domain-2> ... <domain-N>
```
where:
- `<N>` is the number of domain names to query
- `<domain-1>`, `<domain-2>`, ..., `<domain-N>` are the domain names to query