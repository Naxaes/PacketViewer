# PacketViewer
A terminal command for viewing network packets in pretty formatting. Currently in development, and only works for FreeBSD or OSX.


# Build and run
From the project directory, run the following commands.

```
./build
```

You might have to set the file as a runnable first. In that case, do 

```
chmod +x ./build
./build
```

The executable will be placed in the folder build.

```
./build/ted
```

# Example output

### Ethernet frame with IPv4 and UDP from my chromecast.
![Ethernet frame with IPv4 and UDP from my chromecast](https://i.imgur.com/YZIGHGA.png)

### Ethernet frame with IPv4 and TCP (with options)
![Ethernet frame with IPv4 and TCP (with options)](https://i.imgur.com/b42JhBW.png)
