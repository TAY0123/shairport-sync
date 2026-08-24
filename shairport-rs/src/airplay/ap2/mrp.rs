//! Minimal MediaRemote Protocol (MRP) support used by AirPlay 2 type-130
//! DataStream remote-control sessions.
//!
//! We intentionally encode only the verified playback command subset instead
//! of vendoring the full MediaRemote protobuf schema. The wire fields match
//! Apple's proto2 layout as mirrored by pyatv:
//! - ProtocolMessage.type = field 1, SEND_COMMAND_MESSAGE = 1
//! - SendCommandMessage extension = field 6
//! - SendCommandMessage.command = field 1
//! - ProtocolMessage.errorCode = field 4, NoError = 0
//! - ProtocolMessage.uniqueIdentifier = field 85

use uuid::Uuid;

/// MediaRemote playback commands supported by the receiver control surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrpCommand {
    Play,
    Pause,
    TogglePlayPause,
    Stop,
    NextTrack,
    PreviousTrack,
}

impl MrpCommand {
    /// MediaRemote `Command` enum value.
    pub const fn wire_value(self) -> u64 {
        match self {
            Self::Play => 1,
            Self::Pause => 2,
            Self::TogglePlayPause => 3,
            Self::Stop => 4,
            Self::NextTrack => 5,
            Self::PreviousTrack => 6,
        }
    }

    /// Map the receiver's public command aliases onto the MRP subset.
    pub fn from_alias(alias: &str) -> Option<Self> {
        match alias.to_ascii_lowercase().as_str() {
            "play" | "resume" => Some(Self::Play),
            "pause" => Some(Self::Pause),
            "playpause" | "toggle" => Some(Self::TogglePlayPause),
            "stop" => Some(Self::Stop),
            "next" | "nextitem" => Some(Self::NextTrack),
            "previous" | "prev" | "previtem" => Some(Self::PreviousTrack),
            _ => None,
        }
    }
}

/// Build one length-prefixed MediaRemote `ProtocolMessage` suitable for the
/// `params.data` field of a DataStream command plist.
pub fn encode_send_command(command: MrpCommand) -> Vec<u8> {
    encode_send_command_with_id(
        command,
        &Uuid::new_v4().hyphenated().to_string().to_uppercase(),
    )
}

fn encode_send_command_with_id(command: MrpCommand, unique_identifier: &str) -> Vec<u8> {
    let mut inner = Vec::with_capacity(2);
    put_varint_field(&mut inner, 1, command.wire_value());

    let mut message = Vec::with_capacity(64);
    put_varint_field(&mut message, 1, 1); // ProtocolMessage.SEND_COMMAND_MESSAGE
    put_varint_field(&mut message, 4, 0); // ErrorCode.NoError
    put_bytes_field(&mut message, 6, &inner); // sendCommandMessage extension
    put_bytes_field(&mut message, 85, unique_identifier.as_bytes());

    let mut framed = Vec::with_capacity(message.len() + 2);
    put_varint(&mut framed, message.len() as u64);
    framed.extend_from_slice(&message);
    framed
}

fn put_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    put_key(out, field, 0);
    put_varint(out, value);
}

fn put_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_key(out, field, 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn put_key(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    put_varint(out, ((field as u64) << 3) | wire_type as u64);
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_cover_system_media_controls() {
        assert_eq!(MrpCommand::from_alias("play"), Some(MrpCommand::Play));
        assert_eq!(MrpCommand::from_alias("pause"), Some(MrpCommand::Pause));
        assert_eq!(
            MrpCommand::from_alias("toggle"),
            Some(MrpCommand::TogglePlayPause)
        );
        assert_eq!(MrpCommand::from_alias("stop"), Some(MrpCommand::Stop));
        assert_eq!(MrpCommand::from_alias("next"), Some(MrpCommand::NextTrack));
        assert_eq!(
            MrpCommand::from_alias("previous"),
            Some(MrpCommand::PreviousTrack)
        );
        assert_eq!(MrpCommand::from_alias("seek"), None);
    }

    #[test]
    fn pause_command_has_verified_proto2_shape() {
        let id = "00000000-0000-0000-0000-000000000001";
        let encoded = encode_send_command_with_id(MrpCommand::Pause, id);

        // Message body:
        //   08 01       field 1 = SEND_COMMAND_MESSAGE
        //   20 00       field 4 = NoError
        //   32 02 08 02 field 6 = SendCommandMessage { command = Pause }
        //   aa 05 24 .. field 85 = 36-byte UUID
        assert_eq!(encoded[0] as usize, encoded.len() - 1);
        assert_eq!(
            &encoded[1..9],
            &[0x08, 0x01, 0x20, 0x00, 0x32, 0x02, 0x08, 0x02]
        );
        assert_eq!(&encoded[9..12], &[0xaa, 0x05, 0x24]);
        assert_eq!(&encoded[12..], id.as_bytes());
    }

    #[test]
    fn command_values_match_mediaremote_schema() {
        assert_eq!(MrpCommand::Play.wire_value(), 1);
        assert_eq!(MrpCommand::Pause.wire_value(), 2);
        assert_eq!(MrpCommand::TogglePlayPause.wire_value(), 3);
        assert_eq!(MrpCommand::Stop.wire_value(), 4);
        assert_eq!(MrpCommand::NextTrack.wire_value(), 5);
        assert_eq!(MrpCommand::PreviousTrack.wire_value(), 6);
    }
}
