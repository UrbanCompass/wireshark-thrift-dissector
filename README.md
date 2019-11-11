# wireshark-thrift-dissector

A wireshark dissector for thrift messages, **modified for use at Compass**.

This has been altered from the original to work with our `grpc+thrift` internal comms.

## Protocols Supported

It contains a single Protocol that can decode individual Binary Encoded thrift structs; that
Protocol is installed as a subdissector for `grpc_message_type=application/grpc` and
`grpc_message_type=application/grpc+thrift`.

## Configuration

Right now this has no configuration.

## Usage

The original package proposes using:
`wireshark -X lua_script:thrift-generic.lua path/to/your/capture.pcap`

Personally, I just copy the lua file to my wireshark plugins `~/.config/wireshark/plugins/`
(you may have to create this dir) so that it is automatically loaded.

## Known Issues / TODOs

Compass specific wants:
* It would be nice to be able to at least see the name of the calling method in the thrift struct,
  but I am not familiar enough.
* would be nice to have field names rather than field IDs.
* I have not tested this with large and/or complexstructs. I expect that there will be some bugs
  and/or some missing feature.

From the original project:
* Performance is a bit slow with large fragmented messages. This can probably be improved through parsing partial
messages, currently the dissector buffers fragmented messages until the full message can be dissected.
* There's a few types that are currently unsupported: `UTF8/UTF16`
* Only supports the THeader protocol currently, can be extended to support non-headered TFramed messages.
* Add configuration via preferences.
* Maybe make a compiler to take thrift IDL and build a dissector. This will allow for field names, wireshark filters,
and non-framed messages.
