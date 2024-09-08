# cactl

==== WIP ===

A simple command line tool to create and control a local certificate authority, held in local files. No heavyweight CA webserver deployments, no weird error-prone openssl commands, just a simple tool to create and manage keys and certificates for your systems.

This works at a high level. Instead of creating certs, you define entities. Then you export the necessary configs for those entities. At that point, the necessary certs are created, if they don't already exist. If they do exist, and expiry is within a certain amount of time, they are renewed automatically.

This gives you simple, declarative idempotent ops, regardless of if/when a cert has already been generated, when it was generated and so on.

We try to "do the right thing"(tm) as far as possible, so that you don't need to worry about stuff like ciphers, key sizes, etc.  The principle we're following is secure by default, without getting in your way.

This is along the lines of easyrsa and cfssl, but much higher level, lower cognitive load, and simpler to get right.

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
