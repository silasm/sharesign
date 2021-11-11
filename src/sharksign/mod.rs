use std::error::Error;
use sharks::{Sharks, Share};

pub mod data;
pub mod error;
pub mod openssl;
use self::openssl as tls;

// result of signing a payload
pub struct Signature {
    signature: Vec<u8>
}

// dummy type for encrypted return
pub struct Encrypted {}

pub fn generate(num_shares: usize, shares_needed: u8, config: &data::KeyConfig) -> Result<Vec<Share>, Box<dyn Error>> {
    let key = tls::generate(config)?;
    let sharks = Sharks(shares_needed);
    // TODO: replace RNG if needed using dealer_rng
    let dealer = sharks.dealer(key.as_slice());
    Ok(dealer.take(num_shares).collect())
}

fn recover(shares_needed: u8, shares: &[Share]) -> Result<Vec<u8>, Box<dyn Error>> {
    let sharks = Sharks(shares_needed);
    Ok(sharks.recover(shares)?)
}

pub fn sign(shares_needed: u8, shares: &[Share], payload: &[u8], config: &data::KeyConfig) -> Result<Signature, Box<dyn Error>> {
    let pem = recover(shares_needed, shares)?;
    let signature = tls::sign(config, pem.as_slice(), payload)?;
    Ok(Signature{
        signature: signature,
    })
}

pub fn encryptshare(_share: Share, _pubkey: data::PubKey) -> Encrypted {
    // pubkey_encrypt(Vec::from(&share).as_slice(), pubkey)
    assert!(false);
    return Encrypted {}
}

#[cfg(test)]
mod tests {
    use hex;
    use std::convert::TryFrom;
    use super::*;

    fn static_shares_3_5() -> [Share; 5] {
        [
            "0132f031c0bcea77e6575fa0c7fa5275ed6662e270a9ac9cc0d85da1bb8c8cd1d9fbf48382adedcda028ac00e5ff931be7bfdb5beaf54f019eaf1b77b860778bca29908b7154948d991a28a96b2af6b54188a5adac5dad9f16ba11aafc7396a271cd990ff2db5c32133bd558552a564df92d3120bba1f6abf279a31ad726725c8f7f28d290a49a4cef12e3b17908cfc9f00e90b442cbd3a68724e5ca5c37c5a7aed6f0d1ee588b3a57f9aba2bcd1deb45efc5054d5535374d6d53843c589f3b267cd2374b7cb04308cc64746c473b7579a8630c2c4d172cbb09dd6054157a6b312a2df68059448b1aed5b1c87e7ba94df268d1ade566c5a60216089b4d3bb11233bdb206eb0ba446710bf16e63d4e655644968d3eabe757f4650c33791dda035a668607a652d31e6d257bd1601fc988346855a9645d730c046fe481c445e7469ea04b32adee0e114959deb30d056d9ee507bd2fe29598fd877ea1bd5693f467a3ea14ad5ab5c5670e9cbdba13c7a439a3871ee77b3610312f13914a722ce3007815862ff6d29853dbee26259ba3b9fba48185a2926043e2f5dd8d99e871be3876718d7d8e82846a675335db0e1965cd300e4d812851e622344491785bccb934696f3e899f438cfe7d8a68d7398dd11d4e2ddc288a77725ce6b28a10db5f0aad7923fa81ff8550b02c8c278ef40ed8d0ea1775b8096d04a0814f9a7085ae799b31782ec4f97d4a131d5ea1c586edbc4bc03e5dcb225bdafb6dbc396c9f0cb2e4c26c911e727fca9bb66666a90c7a04a83fd80712f7d73e8006223edea3c0e5c294965f58696b7b9876997d3bb2d7de829a172a5000706bbd90a2ab0e12680898682cf0c38fbe700e2690889341acdd9ae63e8a262bc81ac45021af7976c19bc66a26431d6dda648fdbd7664f647ec7837a12d34c7ababefa2448bfb36fe05a2b361fb0389031681b5a26fc06e60a9ed23bdf3210bee57bc69d642f343e1aab7f7c14a08a3dbab37ebd9d802b8ada9af5296249fa4b02380cb616190c9c4b2b8ed787253f2c81ed087fac39e9ad172583af9eac08198cdc387ea96be30531e24aa82e4ebc5268b3537f39365385a129bed5c6f0a223330271856f09bb0f6302d36b6d2ef71c1fb9f7eb87b9478e94d15703fef8c3f49268552dcf1bc2e19054c8cdceb7713c3da3ab5e46d0cb4751cbc642a034d077f1a810ed9cc94a607733164b046824ed2e292c0c2234db1bfa8c2edc211e5920077b7348afe407a35de9993fb471e77ae0b275194c27660d1932b836eaf4706bac4344e9b7e66cf66e28f5b540faa819237ded9a4528de7c7e6291cd17fdc3a7c790e4f0605e3b4e488dd4b1ed8c65ddf60945d55486957d2292084e5b14ae505de4e80477508533169ad69f3a0c6854500c5920deebad050ea97cfb48d8b01c9a529c56d3bd40136ff59cd76f0b20a047fd97c145cd20096f6dbb169869051a3aed49f7927dff559f72f75db966e4be8ac834b0e9efadf2457f1c718f1c9943439b02f80ddc0eaf0c3d4cbfdd3185c89cd00a526518ad6cd124810b4e36ebca05b166dc4efa9ae3ad700e6b1d86da200d3a9a8843cd2b448a2c2af1cdf2fbb3717617b8dba20e106eb6265a18b3858c5101b3a4d75b5a11eb2e78576719be73698ddd4479022d177a987a53964e180af577d70c0abc98a127a001b834fe425547ddca7ad6c4e0c4a9b5e55dc773b8b47a3bfca522fc5638ffd227b62463bbe48da46df0a225fa6b0b5cb6b25b62aef5f16f4b00b45f14f75c828fd8c3055473e8b634f9b4980188348521d1822b72f89775ae1e7c92ebda3460a9e19da5293ec6f898270d373b722e86a63d80c68b40c61f908283b055564de582a7390d692dcb3bada0749c3580f714f7e699d01ef4719b9790be0dd30a8283aa3260c42c07a715c27ec2f6862338649425b4232de1158c551c711dd37e588b886d9eda181095f2a9e331eaa8b533d8c1e0f7786791fd7301f7030ab31ef38b1ab64c223e412e663cfd169cb71a538453116034b909be97ac371c92b785ea16c41cfb606df9927dbb06f9797fe0506f9c4a580799d16b1fe7dbd7606825ce91d1f464948c7fb84b5a8b4c3cd143715f451f652014352790733d35884b5ade5abf0381cdbbffa3de63df65d8021fe5a927420cf78b00f1580dbf26c4e653958467a977a35b5ab01d1aa86e6a3db5495f0a4bb47e49f99175484083e50f5be9fa5d746d47de610d2f13a28c027899fcf0c8795b5af8f3b22adeb82f66647d9e2179cc6c1d8d623600a12a6cb36f5679c4dec6dfe842dbb3d1b59272be7f43e264d1c96c41a24c8dee7c79c899ad79c412f9cee6e4242095d149d90f05af2",
            "02674b0fa692fc8202b18041bd6b13ed90edf18e21a5876582483085c407c311c5207fca2d136f00974a5e07915caba9486d5efba3221656551913b474a36d3871851c26568291b6070d7602a3f2f63d71bc085ed0e94618514b59cd964ee44839ed5db9bfa9ce70c62e4ef840a67f7c7afd884ac8045c04c4f45130736de5d53a089624573822c8c7a74f96ddf09854460979d3c9863988d828d485cf6e4dd75ce27bfafe9486422d7e74cd86f339dbbcdad4f9902289632b55abf8fcf1cb1572a39eb75017b3b9711611d5bdcc3dd66aec97f8270100150797209548eb80ea0b647e67aca58784ada4b50f2288584afdb94c76f57fe2dc686135fdd094b71d65c65259faf84464d2c14b8cca378f92742eb097f21efe6c8081e7c3f0f489c99cb7a286c9c925baaf92027e813e73e605a22a63fe9938be92aa91f881765a29f579dd1c5c2628cd05d27912f4b61eabe824e660ba512b9566e36215a98aa2af1a36688ac1a258103537c19e946d73c35eff9e10bf62e4803679cb83e723a1ba05cdc596c735efc5f2a2ee36c1e22be98176db112df5de2cab624edcd115fdc715609ad20dad74a873e27d2337328218d2e8f4f356d589d8d8262d3f737cad688b9e0182a162048fc9c28fca91fa66d8f091aa06445e44675fc4c0cd38283c843952c9496484ae1606d5983e1e18795ff6017e92fbc6171633671a5e8dec80fc4a336368c03e56bb3c2f8c985a983cd6c83f02e2328609de9379774cce6df1d77cf8a11e54a007089868f621508a95b6d894d19543ba50deb2515dc26b24c893e3e50288de1acf966379af29ef9a8880b59337e541b7fda524cd46d52434f0b8160fe76fd3f7a08893a1658d29c1d0b14f8f6c9976f8376c6e5774c31bc0c69bb26e1b3b1f19a82cd8db5ff75772ebbe4fc8258fd30b4c33c6340fb7be0aa2ce543026671a37a7c0dd824214a39fec70383ec331370a4b5f78b715b3ae50bbd53f743d82ebfd4a4e0d3bff610ad32e6a5d865884988007aea722391cda61475d3b8109f2f44e9ffc089f045421479845efb23558b32cf8c142a7e625788c173c521b00e9d618d607786e8c16855a42c1d8329d8ed58bd35fa2b8224247d959cfd34d47ec920d8b81bc42cb0d78b28815e781953dabbb1942912685c87b304c809ba5cf53e0e7544e21b962ca22939289f431e8093a54e1694b141d464695a39670890734845914f60a263507ce0653e305658cfbe9bb276f50ab7bd60cabfd398d4c4a9f73ebb5b2b569ff675040cb5eb6338bc2cd8b9e25a073b71c137c851de9a20f35a170246193ff5aaee5f6980b5100db6e4963308acdfa96913c58a81e1cd85363488ee4b6cb8d3f237972998acddaa9e856356ed093a10b6adcc5812e0acd958ddcac5fed9d07a97617c8add5f5aab1fc607501c97092a0fd78337d3155b04eda0bc4b51d768f95ed6312b82fd9dee355fc66f69908331aeeb7cc5d738606347c8745a0fcb26d3a12cf10b18594fc4f876a2ed2dad21c9e13767b2af55dd367f38d8b1c8fd4edd6ab99a28b76bf1b7d86b1dca4b68289b549bd2977e680676b40e2ac50ef4145ffb2d656aee4f612a1645fc8ed1a2f57b9e345e1433a05eb176318030b018f11f2490379af5189280ac62c331ec9606b9f880508d67c1e01faf3b856ab34f3936138f60185de8e49aeda1173127aeb5b9fe4d43ab995c439a9f9c75e189ae34227447de5b86ff7e1c9f623dae5c8316633a2c668b779c54d709c20350729795aa90e34471600d26d5cb2a060d3db7654905bc1cc775fd5d8a32d93fc1227a36e67a7b6a5a0d73fa35f69345c7b3a063003831da02a41abf635c51c45c0b2553a6c89901936aad1026f99a4735a717edd15a5c328eff01471e0c730d5a0ede71e1c1f057610f55e7b454b7174b3a03c019a4efc81d1c316a42e7bf7a109921cf026061f8005e39b6e44a495a40d7dd889f7a96cd6210924a70152c15aabfa646ac59a43792bb6d5ce471092c7e68fa2ddf344ea5781067e3d642f3475b847dc034da694512142ea840396d5e2584e2095fbed6e23286cf5d72174c247527f4d069517f5a6fedd0e9895cb589c23196e9e26be49248505fae89980db4fbdd12405b5300b1d4731ad8941f1dfc23cb7cdecd891947297b5b16811f9a63f435154ebf29f60831903ffb73d0523423f6e3a3e35a55c86885a1a01c46803a2e42ffd64d6a30034905f034efd633181c0fdadc8767741a147b61986dbdc190b9e3b8dce04404910f3078911d0dbc1fd56275e1090212fa00c8ff908721497626a0ffa5b07574d4cfbe2aa9d5de6579ae77d6e55919847929b3f4719bebebbe40ce169e9a07f",
            "037896134b0354b0a3af91c128c200b82dd9da3a10586ed909d5340952a662ed1696c200ead1f5847523b34c37e269f7eea3e9ee39991d2382f845bbb8bb2bc58ae2e2dc70b8564cc87a67f8e39b42ca5d78fe9526d29ac202a43253216d43de102aafdf2503db01fa23b4cc7efe1d66ec9cf61c2392d0ca5deca545cc07a5f3ec2e959990f6ebdd65ff83538b9f04ff8174bc0ed214c159096d767ef22dc43b886081532884632c2ad2eb165e56c80cac1fc89f3737e95484f9d2f469410aee2525f484b2a9fee48f9c01de1ac8cbb49c32f3538f9524b9c159dda7448d50217e89e205fe78aa53411346901d80bd5669a8aaa1286d16422c1c4c07d9fc3063794a86077d988170d5b0dfd3e6b401be7c17e102698fd35688876f8e1742519556bbaeaea6937c36178b883ae984ac156c64068cdc14412ea0359b8d801101024e0a037eba829fb6bb79e41717d6b630da3d40cbfb46c77c737a20a788f888e655a1456f27f4560ce9937755c57505082ec5262d236d8ba2930eeb6696bec1dae7f7e613fa4c0d9b2526a33e329df502882cc05742b3a141a6f6df23603e500f5d0c7d6eb4df3849308915d487c1affaeb6b69a8818da4caec2b558a858553435702bd29606a89037b1172807853303a511d05fbaf6254f076bf54b8eeb4f917fc0b5261e8bbee1ebd5d98a23fc5c5372527486a0866654672d0856193626e2b2ec9fd1119dca0bf8beedd8701198826fe8bec0159739e182b9182b771e0e6ce1e7bfbad3b0bca84f465a5e7f459bc7b6c7cf2cc7b9eee84a23bc547206bf3959bb4a36122c9275b5bb957d883af159d7f99c49317d971177a96ac5b5583360ea78aac351e48c35fb8a39af4416264767451e5b8a01acf022915d7353b890d9c78456fc2e9c987a74ed9086e62faf1fb89895a3d53c4ccd5f8fedfd2054e35316dba578d4f4b47270aa18842ac42421cb399d1409f11915381bfbe997ab55573ae72655355272bcbe0b7b7acdd20ed4ca8faec576dc0d6128f32dba34781ccda28896e3955310b1ca613d7c48040892e2e19b09a4cb87e079a003f246ae17ee19586895b98a08767c9d2bf578f189f41e717d8c7abe9bc16861ed3a2d3ba27c024d3ecc934ac77b9746136129bc9d1129d087a31a6d4c6480aba7ca2501e443f3027eb13405323b7f4803b513be15db9b067f44537065313aa8bfdae238ec89497ffe84c128aee06ad323de644a4a65cb75b193cac8ec911966c03ef60011deb156817a6acacd0ba43cedb63c7a083ec94f2f9f31b22c4316f4ce49c12b54969d3f5c8fd03049de172ecaf3a4d78bb4ee50f7d3167685d88938a1d7dabe21a184062a44bafb438a0c4906324ff15897c5c1d8465378d4d31b8ae6151ac836974b8556645cac5f631c4ac50c3147b6b1030714e8ff8b1113f47cf16ae05a1748f762a8de049e816572ebb25a8bbb115f2c51e47321b816c674320a623824e174218fd170e5699519cfeaba9848c7377238634f342376f3b8518931980e1fbae59e94a4ec02f0c734699c8081960d7a12b3ccb760b45dee69e050145a6efba44780890448fa749a132a7131e75f7b3432a9bc7cc902bb7be1b9aaac96e7b784e05f119647f8b607f41b20070c769a17ce7962dc614769eb75041a8d43113d8659a413f41006e58b03e7a4299c28634eba97d4e40882360b4b1235bb9aaacf9a0a9400af933ab87ff1cc55d896c8356a27ec4d795252376c4264b285c6d00933474b2962e120f7783d23e7a102b76ff0ece6a337fffd6c4f8f3bb4a650a05cb623b858f777055fe70b707f6025872b2e93b55013ab58d5bb6e037d71f0014787373108e0528491141cd2e6311b493812cededf8fe4272a293f209d2999aa46fcebb49bcab1e38ae5fbfdb86831dc8154f2f4a4f36ed607fd6befb748318f751fbea22b374ef8b94e7aeec84b161bd608d0004f6b110abf1168d8fc514164a9cc374429aeb5c99f5d48c58362f939936e82df74731bcce11d2070bdb744d7629ad7e3e6404dbe6f485b6e0ac2db98e971d571c79347f009d89c73870387c3a6e93cf120517a39e94ef689f3fd7f4fa06cc867fb2af79fb6da7ebec6a98c209761b0e62c9ababf979fbbac47272fdf2a8adeed4aceb7e688eb58070860f9b196033b7d3d40e7cf94df1c9d0c589af0aac344b0ef84eeaf21a8da1d590ee47276509cbeb3468b0c3e589fd8109c535e9ff79de1fd5f2e770115e868f2700b3921d1946c5673d2a675c7ca1487f506fe7919eef2292716884df6c6282b0f5be224d0d2dc5b29e087a111218b60281ce11609bd311746a87d10020e8a19d2b1f899ae2e2fd32dcb7f7e03551d434d787",
            "0474c2010b74c860a593580fd6e228266b4abb7589f3e82aebf712eea5b0121644e77c7a5e2483b6c514389ccc9629dd2e07117f048aed37f7fa1e925a58ee7427d1fc1d7cf193489baf0e2b06ad14b6583877e0a2a66d089f3acf9c6e11a4e556141ca404a2d4469e0ef78e7c4aa47dd5e230742c59ba0012f8b03fa3fdc092f08f9a4921a56eb02fe45c64b36d47e77abddb74c645d48993d87325570a761740a3b272683a5f777ba625709c008022d82fdba555abaf269998e8ba435a58172345f6d808bd3d7ddba95e62cceab7729b79e319e214825f33cfaa5133c0b6259d8e594eddbd66e6291d8116f3134febcf4b53a40ade12deb8981b8d539c5b806e2d30947301d946b168555a0b6604447c7c9a46f075de7e90aeb0992ed7ea5468d492cde53e29a46774ada044f249e8bc41de0e1bf69dfa976dc2a7ef99ee601fec549a1e5c9e7b5665c8cfd0362727f42366da8cb4fdd5d288e9af2152bf2e54fa30f0215728999beb7b7ef3802b0c9b19757efc3e24ba4463118563f26bb4696a7b74f0fc335ae290c15e95689eedb310e27c53ddfb74187ca063bfabc256c94b807e25e54944979cffe9f1411484ac0e5810bcf194ed1a7d19d33f10743658e73e842c81d71d7e36f34310560b2bafffd4f977c88e1159f9e56e5a7dfe12482cb97300d11502e11b02546b6615979b81aaadcd8a6d5b2e6978b938545ce5e25c9000cb45b2166a754347a8900ce4ace1b197242d52cdd0c9e0a0ffa00bb6e3ade7045f6e15a10609030780893842c1497af48c3edb8f486e31fa5d4067b0005adc1c46ab219e20fd87c6c52bdd438b68c6acbbc7a50ca33c11d0cfec94fe0c95c2a6740cec6adbc7b718d2da0df5ef3998b0dc5d90f3bd50e569be65e07f90cc1bcc70c79a9bffa1c4a41924a3f2e9a1edaa752dd108387c3d3ed4fcaccca5ce3878717e9c7254d7b95a85929f8a3e64b972541d16995b3edac2a6760c37d3ecd9aeffe031f2993fa92bb180ab1d1c61d5b14a297e124a069686e8ab3a940e1aa5af615c704998813027eae11d56b66024470eaea8188133c0414704e37641b40fed81605d8d3f3d3534c446f8d63b728b7ded896a0795511c6f6877b84fe1ce7fd63ad49a33ec0139fe70f61c1e5932467774007b54255e643cdc1c342f149f016927b684dbb7d515e71ded393d0f9a0080b7aa1ccd54504c6db584096cee1627dd3a8afe4d4bf138e4315b8942aa639ee098db63437a0448cffdb5159289bca747cbbb4559491ca64efe8aceb767fb21a673229ee56008bccc4ac2c30496fc4a52086e51bdd07a4f535d0f44ba1435c29d654cdbf5cbd77ae700ea3e8a41608b5c6e5529cf6357d35ffed961bb39cf8c53e73862bb11e27ea18f63f4971f8819f9e6a2e70d2ae59ececee91d9428f27bce437729f603b60d352e50f67b5028a5bbdf7b93a62abd83802eabe95d5a7fb57e98c05de8ccbee1d039a09f637181430d5c607fc40298724a92d37a5af99360f9b1a35f6923e7e7f4cda70525f8878d85a1ba071a9c30c105664c63054c0d6db8c3706408b30dd85a06db339fbc69d1b5a236b3a8cb02fab9d95a35660bbc7d468c50682f8b9cbb75c683efe25bf121760371ad47bdcff7622c8e9fbbeb89aafb1b2034ce679505b3948cb3a2a9700c9f3b0b2a93cef05f5e9a4379788576d614c4b84e0e68de4dfbbb5fb1a663d267e83e24aec60cf9c734fa62cffc279c7ec62fb0593e1c1a65df8f111c4c983ba651e8250b91f0fa951a176b24a7f3ae8fef95d97095b0adea971a5a4faa9b3e377fc374f36c7067ac8dd5eb41b8b1e15535afe8e0975b47facdd7f997bc58b8b60d4892b30cb85dcfe1772db7c7d1844b0537c283c5cb439a34aa705af326b0f3ac1008832f108517cc1efa84e8e712abd1bf062db82f12f9bfc250a5e9d9f10b38d14ac4a81ebbf3a6f371ba1d3e9bcfbd315b61d749e8a1cc0efc92cdcdeb1cd98ea5f2b341a27d9b8211efaf064eae8c66c66bf9bfd4a5b87df75e119ce7b330845a8acaf13478234ead96880a6838cadb3c3d2a5861c7b84974922cbcb59b38876aa4ac7d31b203d8787ed70e0ed72f29e2090e9f150961c9bab6dd851b6567a0e27936124c3bf3102256ddfc8be880d7a6a406f9a0a4c007449ed665a0b6fb9c1df09beefe624e8e102feecc5cfeae77f94f69b5785d15e72721b66cf04e2bd6448283a2ae821da31fa51c71e50f303e062e11f26c14bfb42ce6181ad9616347eed074a7b71cfdea2824503ed9c93781eab4780c05ec418196d98b7b48070fd119b26d70766c4d5afec420a9b1b5875c1efe6ceb37189612e92dfe87d5740721d03e562929bbba",
            "056b1f1de6e56052048d498f434b3b73d67e90c1b80e0196606a16623311b3ea9751c1b099e61932277dd5d76a28eb8388c9a66a9e31e642201b489d9640a889dcb602e75acb54b254d81fd146c4a04174fc812b549db1d2ccd5a402d93203737fd3eec29e08c137a2030dba4212c66743834e22c7cf36ce8be0444a1c9780b426a999f4e66ba7a58dbc90a1e502db4cbdc01ea9ddd72c58429dd1de6a49fffb942148dbbe2aba197c0abaab44a571f5c8eac7c3f2becf11363491b6d6ea99ec74c39cebea03702025234e696bee41106da787b24a80a6f3f50157633fa666eee863c52c8f604b31c5aa7289cc1baaf75b5ab573d7cce640fce562775af4dcfe72a1e4caf4611c52b619c10527e58a687445cbd36be4f34498a838d4c9613208a2d89ee58a647028df6d27e42c48961bd587f2e1397be46aa5f2c8d2eefeb54ba49f8af8f8f82900e8ce55ca33568fbcc63ac071cda3113cc711ab1d002095671b6d1d15c7012685474fcdb5a2985dc7eb23cd4360314b98e1143160126f0bd48b5058f1cd85d10435148c5666174006ba4af93a3c9b841915e8319c0e806f9e812767c29c9705a5d4f7971e41b23966958dc54b6ba9b9ff2e706166c9e98a1d847b822fed895a91cce50e09f9ff5dc90e737b049cf49e867082711b8ce13b818d75225b8cee550a5a9302c84abba9ff48a79c553e2a1f0b6fdee78626dab23286a60e7912a74412ddb41258f311b8149a555f744fd8c50b6821155b402d1caf812ebdb730c5d82d6a0450c1245a118f75a159adb41a65d55804a97f160f5cb6780b7df5ba78c953183d7f37a91e405e416235daeda929befd67fb5ebe5b5248bd1089fcb9b38fbdf0c54861ba79b932d4e711910abf689dfa12469f9e2c2b785ae76f358617b51069a3933d2cacb9b72fe09218f5e251ee06b6ed5b6fb83b339c44499224027c9583f4730c8a4f31e6b5c3ab03fc06cc95a23671e87293e29142ea817f413a507774b3e1e66673683be91d6162bf69afae62167439754bb1131d12c264c023e4a9360de3b74be60c3d77cba185f13a2ede5994194055698aab8629865fcfd80ced8e810675ce0425560457ce3493eb054eb1f7ed8ffc14c6401650d4f39c75660b2422c4e1938d451923bba97b796fa45ebec29d56f7323c90bf1d25298702f32262ec4c7c049ff60d4bcc1cccbaf8aeb7b5cfac85d09f626e0960c8a5ac5904bdece53005bbf97cfd185d0b27ddee8d3dbcc330f6911ff5401198fa7e14fc2051bfbb824a696a8605453a5397a58bc4f1af37ef4c4b0b0f70acab8d9aaa1ae83d3169bac7f58167ffa03a64c24b47b6f795a7f10b97508c8c1dda7c74896ff5d96c4a8f5878be714da808a1de8680415a3aed149aff251ccdad10ea31f0cb4ed1734e677bcd5adb51ed2984bddbb3390034ebbb6653c2ffc573b266819d5730ec728933c5f608448046bf11197f27c71687ad5d1d0c22d552ef7a607f8dbc8ea44e5ee1dcd1b0bcfceb5bdc3cece2b636e96860675a2781894c1ea4b6033d68d3d1151fb79f394958cfdd663537722620348528b554480001349efe7ae7d342752d541b7ef8bfd8a8666910b2f82f3b2e3e61cbf8f81ae2ddaf03526a9012d90780de75ec46564c0df48c6629418d9d5746564e0a825c0044f64eb76ced0531994721a7a4ea76170f76713846f6abe8c5a0de6bb5c39ca89ae7e1372252fd49402ae6691c04d1d5ed14aa22152f1c78d066540a1049ea9f41efe0f8dfc7678f6ab7da2c3f55d33c694bf0aca2e37d5bbd7db31fc6de5d5acecb69e322057691fcd4ffc97211fc0854db4330e916ef2d4d6aa0e64ede21ce8ee3c086e01dc63273c304b2dc74b5ad80ed7edadee1134a46bc4c160bcd377bb87b7db87518737c7d2c1d88ced399db32f326d877ae0d48a6e867e0e9c9808fc0ede651acad7f2a94eecf64c1519132fea1033a090f0e7a271ea4427328b670b0abd6f6d7d60a8dc57dfe9792585e2c3424c7d8203a105f7116d222b1e1897269dcbed3c456dbb73bcd9b183c546baa9dfc950f230e43eca3408404291d39298f5b67adefdbb919bbaf08f0e0d7d84c8c7f24ed9d8a138dfc1de1b71d89e828d61d3a574c82d43f5df23bfc3ee997bc0285ae420f60ea2d3144ca73ca8a563ad4071ca97ec36f42036ad0197ee43f02a63d138d41a6a1fda65ad686f79cc4a0279dc5e2f31603ef51dec3918b4ad44c9d6d7e00b47f96b06ad083627b6790b8e8c638879539b932ee620648d244a949b8955a6884c4c88e3dd0a589de8c7bd82947f2eb133c6aca7a3c2fead406d2a411125882e6da8439f924ffa211dce154233dfe160e6dd407e694f4cc42",
        ].map(|x| Share::try_from(hex::decode(x).unwrap().as_slice()).unwrap())
    }

    #[test]
    fn test_generate_shares_rsa_2048() {
        let config = data::KeyConfig {
            kind: data::KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        let total_shares = 5;
        let shares_needed = 3;
        let shares = generate(total_shares, shares_needed, &config).unwrap();
        assert_eq!(shares.len(), total_shares);
        recover(shares_needed, &shares).unwrap();
    }

    #[test]
    fn recover_static_pem_3_5() {
        recover(3, &static_shares_3_5()).unwrap();
    }

    #[test]
    fn test_sign_shares_rsa_2048() {
        let config = data::KeyConfig {
            kind: data::KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        let shares = static_shares_3_5();
        let shares_needed = 3;
        let payload = "Hello, World!".to_owned().into_bytes();
        let signature = sign(shares_needed, &shares, &payload, &config).unwrap();

        let pem = recover(3, &shares).unwrap();
        tls::verify(&config, &pem, &payload, &signature.signature).unwrap();
    }
}