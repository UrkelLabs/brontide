use brontide;
use hex;
use std::str::FromStr;

const PROLOGUE: &str = "lightning";

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

    let gen_key = || {
        let key = brontide::SecretKey::from_str(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )?;
        Ok(key)
    };

    let mut initiator = brontide::BrontideBuilder::new(ls_priv)
        .with_prologue(PROLOGUE)
        .with_packet_size(brontide::PacketSize::U16)
        .with_generate_key(gen_key)
        .initiator(rs_pub)
        .build();

    let act_one = initiator.gen_act_one().unwrap();

    assert_eq!(hex::encode(act_one.to_vec()), "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");

    let mut act_two = [0_u8; 50];
    act_two.copy_from_slice(&hex::decode("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap());

    initiator.recv_act_two(act_two).unwrap();

    let act_three = initiator.gen_act_three().unwrap();

    assert_eq!(hex::encode(act_three.to_vec()), "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");

    // assert_eq!(
    //     hex::encode(initiator.send_cipher_key()),
    //     "1f33627bc124e43ab1024fded2f5c0d6730430f3f4cb85172b10e77c055b3b65"
    // );

    // assert_eq!(
    //     hex::encode(initiator.receive_cipher_key()),
    //     "5b943fc7215b1d55f7b440d43ad0057d6ef1cfde0e12ab69b1db6b4578e84469"
    // );
}

#[test]
fn test_responder_successful_handshake() {
    let mut ls_priv = [0_u8; 32];
    ls_priv.copy_from_slice(
        &hex::decode("2121212121212121212121212121212121212121212121212121212121212121").unwrap(),
    );

    let gen_key = || {
        let key = brontide::SecretKey::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        Ok(key)
    };

    let mut responder = brontide::BrontideBuilder::new(ls_priv)
        .with_prologue(PROLOGUE)
        .with_packet_size(brontide::PacketSize::U16)
        .with_generate_key(gen_key)
        .responder()
        .build();

    let mut act_one = [0_u8; 50];
    act_one.copy_from_slice(&hex::decode("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap());

    responder.recv_act_one(act_one).unwrap();

    let act_two = responder.gen_act_two().unwrap();

    assert_eq!(hex::encode(act_two.to_vec()), "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");

    let mut act_three = [0_u8; 66];
    act_three.copy_from_slice(&hex::decode("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap());

    responder.recv_act_three(act_three).unwrap();

    // assert_eq!(hex::encode(responder.recv_cipher.secret_key), "1f33627bc124e43ab1024fded2f5c0d6730430f3f4cb85172b10e77c055b3b65");

    // assert_eq!(hex::encode(responder.send_cipher.secret_key), "5b943fc7215b1d55f7b440d43ad0057d6ef1cfde0e12ab69b1db6b4578e84469");
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

    let gen_key = || {
        let key = brontide::SecretKey::from_str(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )?;
        Ok(key)
    };

    let mut initiator = brontide::BrontideBuilder::new(ls_priv)
        .with_prologue(PROLOGUE)
        .with_packet_size(brontide::PacketSize::U16)
        .with_generate_key(gen_key)
        .initiator(rs_pub)
        .build();

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

    let gen_key = || {
        let key = brontide::SecretKey::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        Ok(key)
    };

    let mut responder = brontide::BrontideBuilder::new(ls_priv)
        .with_prologue(PROLOGUE)
        .with_packet_size(brontide::PacketSize::U16)
        .with_generate_key(gen_key)
        .responder()
        .build();

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
        let packet = initiator.encode(hello).unwrap();

        match x {
            0 => assert_eq!(
                hex::encode(&packet),
                "186a811dd5ebcd7c79b728cc8b72178ef5f8a447efac0f9b5477046ce72596296844e1702fe463"
            ),
            1 => assert_eq!(
                hex::encode(&packet),
                "e338507655712eaa0ddc2f8d408599e80a0e2662afc110add447e6a0ed512c46a9bdacd4cb946e"
            ),
            500 => assert_eq!(
                hex::encode(&packet),
                "46aee83987990b46271f678d1303d3e94ba4c45bb20d23ec21ca2b5f6de5cdfdad83183569bea5"
            ),
            501 => assert_eq!(
                hex::encode(&packet),
                "2a05bf99a1815b4781c1ac27547755c8a3ba86ede8c309880e6ab866cfa233036924769652601e"
            ),
            1000 => assert_eq!(
                hex::encode(&packet),
                "bd2be824ec969430f9c4a4bd34eef8bbee4811dc287f98bbb718abbd5c8b78a59dc1eaf0d74375"
            ),
            1001 => assert_eq!(
                hex::encode(&packet),
                "b837d23ea6d5de0fe380c91abe9110ce519791d533ed151ddab4d9172c5561457dda713bfb7ce0"
            ),
            _ => {}
        }

        let message = responder.decode(&packet).unwrap();

        assert_eq!(hex::encode(message), hex::encode(hello));
    }
}
