"""
Command line interface for dns_cache
"""
import argparse
from dns_cache import DNSCacheServer


def main():
    scripts_args = args()
    s = DNSCacheServer(scripts_args.ip, int(scripts_args.forwarder_port), scripts_args.forwarder)
    s.run_server()


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--forwarder', help='Ip of the forwarder server ex: 8.8.8.8', required=True)
    parser.add_argument('-p', '--forwarder_port', help='Port of the forwarder ex: 53', required=True)
    parser.add_argument('-i', '--ip', help='ip to run on ex: localhost', required=True)

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    main()
