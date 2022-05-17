# `jagian`

## 1. Add VirtualBox VM

- 4GB RAM
- 4 Processors
- 100GB VDI HD
- 128MB Video
- 3D Acceleration
- Bridged networking
- Bi-directional clipboard and drag'n'drop

## 2. Install Debian

- Debian 11 / Bullseye
- Hostname: `jagian`
- User: `jagaro`
- Gnome desktop

## 3. Configure

Edit `/etc/local.conf`. See [local.conf.example](local.conf.example).

## 4. Run

```sh
sudo apt install -y git
cd
git clone https://github.com/vjagaro/jagian.git
cd jagian
sudo ./jagian.sh
```
