use brontide;
use hex;
use std::str::FromStr;

const PROLOGUE: &str = "lightning";

// should test initiator (transport-initiator successful handshake)
#[test]
fn test_initiator_successful_handshake() {
    let mut rs_pub = [0_u8; 33];
    rs_pub.copy_from_slice(
        &hex::decode("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7").unwrap(),
    );

    let mut ls_priv = [0_u8; 32];
    ls_priv.copy_from_slice(
        &hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
    );

    let mut initiator = brontide::Brontide::new(true, ls_priv, Some(rs_pub), Some(PROLOGUE));

    initiator.handshake_state.generate_key = || {
        let key = brontide::SecretKey::from_str(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )?;
        Ok(key)
    };

    let act_one = initiator.gen_act_one().unwrap();

    assert_eq!(hex::encode(act_one.to_vec()), "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");

    let mut act_two = [0_u8; 50];
    act_two.copy_from_slice(&hex::decode("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap());

    initiator.recv_act_two(act_two).unwrap();

    let act_three = initiator.gen_act_three().unwrap();

    assert_eq!(hex::encode(act_three.to_vec()), "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");

    // assert_eq!(
    //     hex::encode(initiator.send_cipher_key()),
    //     "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
    // );

    // assert_eq!(
    //     hex::encode(initiator.receive_cipher_key()),
    //     "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
    // );
}

#[test]
fn test_responder_successful_handshake() {
    let mut ls_priv = [0_u8; 32];
    ls_priv.copy_from_slice(
        &hex::decode("2121212121212121212121212121212121212121212121212121212121212121").unwrap(),
    );

    let mut responder = brontide::Brontide::new(false, ls_priv, None::<&[u8]>, Some(PROLOGUE));

    responder.handshake_state.generate_key = || {
        let key = brontide::SecretKey::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        Ok(key)
    };

    let mut act_one = [0_u8; 50];
    act_one.copy_from_slice(&hex::decode("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap());

    responder.recv_act_one(act_one).unwrap();

    let act_two = responder.gen_act_two().unwrap();

    assert_eq!(hex::encode(act_two.to_vec()), "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");

    let mut act_three = [0_u8; 66];
    act_three.copy_from_slice(&hex::decode("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap());

    responder.recv_act_three(act_three).unwrap();

    // assert_eq!(hex::encode(responder.recv_cipher.secret_key), "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");

    // assert_eq!(hex::encode(responder.send_cipher.secret_key), "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");
}

//TODO move this in another file, or above these functions -> Setup for the below encryption.
fn initiator_setup() -> brontide::Brontide {
    let mut rs_pub = [0_u8; 33];
    rs_pub.copy_from_slice(
        &hex::decode("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7").unwrap(),
    );

    let mut ls_priv = [0_u8; 32];
    ls_priv.copy_from_slice(
        &hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
    );

    let mut initiator = brontide::Brontide::new(true, ls_priv, Some(rs_pub), Some(PROLOGUE));

    initiator.handshake_state.generate_key = || {
        let key = brontide::SecretKey::from_str(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )?;
        Ok(key)
    };

    initiator.gen_act_one().unwrap();

    let mut act_two = [0_u8; 50];
    act_two.copy_from_slice(&hex::decode("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap());

    initiator.recv_act_two(act_two).unwrap();

    initiator.gen_act_three().unwrap();

    initiator
}

fn responder_setup() -> brontide::Brontide {
    let mut ls_priv = [0_u8; 32];
    ls_priv.copy_from_slice(
        &hex::decode("2121212121212121212121212121212121212121212121212121212121212121").unwrap(),
    );

    let mut responder = brontide::Brontide::new(false, ls_priv, None::<&[u8]>, Some(PROLOGUE));

    responder.handshake_state.generate_key = || {
        let key = brontide::SecretKey::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        Ok(key)
    };

    let mut act_one = [0_u8; 50];
    act_one.copy_from_slice(&hex::decode("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap());

    responder.recv_act_one(act_one).unwrap();

    responder.gen_act_two().unwrap();

    let mut act_three = [0_u8; 66];
    act_three.copy_from_slice(&hex::decode("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap());

    responder.recv_act_three(act_three).unwrap();

    responder
}

#[test]
fn test_encryption_and_key_rotation() {
    let mut initiator = initiator_setup();
    let mut responder = responder_setup();

    let hello = b"hello";

    for x in 0..1001 {
        let packet = initiator.write(hello.to_vec()).unwrap();

        match x {
            0 => assert_eq!(
                hex::encode(&packet),
                "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95"
            ),
            1 => assert_eq!(
                hex::encode(&packet),
                "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1"
            ),
            500 => assert_eq!(
                hex::encode(&packet),
                "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8"
            ),
            501 => assert_eq!(
                hex::encode(&packet),
                "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd"
            ),
            1000 => assert_eq!(
                hex::encode(&packet),
                "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09"
            ),
            1001 => assert_eq!(
                hex::encode(&packet),
                "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36"
            ),
            _ => {}
        }

        let message = responder.read(&packet).unwrap();

        assert_eq!(hex::encode(message), hex::encode(hello));
    }
}
