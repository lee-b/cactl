# cactl

==== WIP ===

A simple command line certificate authority tool.  This works at a very high level. Instead of creating keys and CSRs and certs, you define entities (root ca, server, client). Then you export the necessary configs for those entities, for whatever you need a config for (nginx, your web browser, your VPN client, etc.). At that point, the necessary certs are created automatically if they don't already exist, and you get a directory with the certs, keys, config files, and a README (or whatever suits the target system you're trying to configure).  Simples.

This gives you simple, declarative idempotent ops, regardless of if/when a cert has already been generated, when it was generated and so on.

This tries to "do the right thing"(tm) as far as possible (choosing appropirate expiry times and key lengths for CA's vs. clients, for example), so that you don't need to worry about stuff like ciphers, key sizes, etc.

The principle we're following is secure by default, too simple to get it wrong, and making it so quick and easy so you'll enjoy using it, and find it better to do things correctly, rather than throwing together your own custom web server config with no TLS, for example.


## Quickstart Example

```
cactl new-root-ca "My Root CA"
cactl new-intermediate-ca "My Intermediate CA"

cactl new-server "my.server.com"
cactl export my.server.com nginx configs/my_server/nginx/
cactl export my.server.com openvpn-server configs/my_server/openvpn/

cactl new-client "my mobile"
cactl export "my mobile" browser configs/my_mobile/browser/
cactl export "my mobile" openvpn-client configs/my_mobile/openvpn/
```


## Quick install

- Ensure that you have `pipx` installed (or use a `venv` if you know what you're doing)
- Download the latest *.whl file from the github releases page for this project.
- Install it with `pipx install <path-to-whl>` (or `pip install`, if you're using a `venv` and know what you're doing)


## Build and install

To build install `cactl` from scratch, make sure you have Poetry installed, then run:

```poetry build && pipx install dist/cactl-<version>.whl```


## License

GNU Affero General Public License, version 3 only.  See LICENSE for the full text of that.

The LICENSE file is overrides anything I say here, but the gist is essentially that you can use this any way you like, except for trying to profit from it in weird, sneaky, one-sided ways.


## Contributing

Contributors are welcome (as long as you're abiding by the `LICENSE` file with your contributions, of course).

- The guts of the core key & certificate handling code is in `src/catctl/db.py`.
- The main exporter code for different target configs (nginx, apache, VPNs, mail servers, etc.) is in `src/cactl/exporters/`.
- The rest is mostly boilerplate/framework code that you won't need to (or should try not to) touch.
