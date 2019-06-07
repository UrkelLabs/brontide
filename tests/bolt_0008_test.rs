use brontide;
use hex;

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

    // let e_priv = hex::decode("1212121212121212121212121212121212121212121212121212121212121212");

    let mut initiator = brontide::Brontide::new(true, ls_priv, Some(rs_pub), Some(PROLOGUE));

    initiator.handshake_state.generate_key = || {
        let mut e_priv = [0_u8; 32];
        e_priv.copy_from_slice(
            &hex::decode("1212121212121212121212121212121212121212121212121212121212121212")
                .unwrap(),
        );
        e_priv
    };

    let act_one = initiator.gen_act_one();

    dbg!(hex::encode(&act_one.to_vec()));

    assert_eq!(hex::encode(act_one.to_vec()), "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
}

// const rspub =
//       '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7';
//     const lspriv =
//       '1111111111111111111111111111111111111111111111111111111111111111';
//     const epriv =
//       '1212121212121212121212121212121212121212121212121212121212121212';

//     initiator = new Brontide();
//     initiator.generateKey = () => Buffer.from(epriv, 'hex');

//     initiator.initState(
//       true,
//       PROLOGUE,
//       Buffer.from(lspriv, 'hex'),
//       Buffer.from(rspub, 'hex')
//     );

//     const actOne = initiator.genActOne();

//     assert.strictEqual(actOne.toString('hex'), ''
//       + '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9'
//       + 'cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c'
//       + '6a');

//     const actTwo = ''
//       + '0002466d7fcae563e5cb09a0d1870bb580344804617879a14'
//       + '949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730'
//       + 'ae';

//     initiator.recvActTwo(Buffer.from(actTwo, 'hex'));

//     const actThree = initiator.genActThree();

//     assert.strictEqual(actThree.toString('hex'), ''
//       + '00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d'
//       + '5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38'
//       + '228dc68b1c466263b47fdf31e560e139ba');

//     assert.strictEqual(
//       initiator.sendCipher.key.toString('hex'),
//       '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9');

//     assert.strictEqual(
//       initiator.recvCipher.key.toString('hex'),
//       'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442');
