/** @warning: this file was automatically generated. */
#include "field.h"

#include <ristretto255.h>

#define ristretto255__id ristretto255_##_id
const ristretto255_point_t ristretto255_point_base = {
		FIELD_LITERAL(0x0000485cca7e8859, 0x00041dc396dfb8fc, 0x0005584743ad3a93, 0x0006ae1e23d9233c,
					  0x00056f798c3a929c),
		FIELD_LITERAL(0x0004ccccccccccc2, 0x0001999999999999, 0x0003333333333333, 0x0006666666666666,
					  0x0004cccccccccccc),
		FIELD_LITERAL(0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					  0x0000000000000000),
		FIELD_LITERAL(0x0004f837acb251cf, 0x0000dea88db96efd, 0x00019b5df567eff2, 0x00059babaf1be1f1,
					  0x000342e2875657f7)
};
const gf_25519_t ristretto255_precomputed_base_as_fe[144]
		VECTOR_ALIGNED = {
				FIELD_LITERAL(0x000787c06838438e, 0x000079b93ae8d43f, 0x0006ce4230c8d2e4, 0x0001e958b5ba51e1,
							  0x000581f2251d4761),
				FIELD_LITERAL(0x00028065bd02efcb, 0x00072c06ae982429, 0x0001a39392af7f7c, 0x000398aaf36dab32,
							  0x0004c8a8c4525fae),
				FIELD_LITERAL(0x00006ff0bb7501fc, 0x00044e6268755a4b, 0x0007e0db395959b3, 0x0005f7807150348a,
							  0x00056f78b81a7a18),
				FIELD_LITERAL(0x00013c159d969f7f, 0x00038046e416d34a, 0x00030a05d3333cd8, 0x0003fc17afcf330a,
							  0x0001456fcd6c2c06),
				FIELD_LITERAL(0x0001b3b052f3a00d, 0x00050d154cc33fb6, 0x000570a09253802b, 0x0006af26330b8f09,
							  0x000503fdb7977d73),
				FIELD_LITERAL(0x0006efde66a0b284, 0x0003f75278c5b57a, 0x000615404a959ab1, 0x0007366d656ec17f,
							  0x00077638e2d52a04),
				FIELD_LITERAL(0x00002d288a8a8e1c, 0x000029f655eeea29, 0x00069ca769b47ee2, 0x0002d41c299b6574,
							  0x0002fcdb7d8bda37),
				FIELD_LITERAL(0x0005883fa323a11e, 0x000241047ad9c769, 0x000233d3283fbb6d, 0x000041bda7280e1d,
							  0x00018a85382540f5),
				FIELD_LITERAL(0x000398ee02172d95, 0x00038f1cb6853c1d, 0x00066b51fca8ad2e, 0x00035176a3f540ea,
							  0x00022227f7ee52d9),
				FIELD_LITERAL(0x000790607ffeebfe, 0x000725f8959cf0e0, 0x00016b68dcd68a0f, 0x00046f439e78680b,
							  0x00026be3a14518fd),
				FIELD_LITERAL(0x0002216f73946c7d, 0x0000f4eb865cbfbf, 0x0003c96750df440c, 0x000655188ab63a68,
							  0x0002a93e3b59098a),
				FIELD_LITERAL(0x0004e738f3d06b92, 0x0003dc62717f856b, 0x0003e77175c6195f, 0x000261d11fdad1f7,
							  0x0003ff975f3e99ff),
				FIELD_LITERAL(0x00031becbaeb1b98, 0x0007912ee9ea6632, 0x0004e42e201b640f, 0x0007e5a0ef458ef1,
							  0x000383f3cebfcbef),
				FIELD_LITERAL(0x00004a9f30d26d26, 0x0001838b85de7867, 0x0006904531c39e2b, 0x0000b5c478c98d49,
							  0x0007d059931f87d8),
				FIELD_LITERAL(0x000740d5eeae1f56, 0x0004b490c85d90e3, 0x000136df23a50d87, 0x000495a021130ba9,
							  0x0007d8b1c66d2535),
				FIELD_LITERAL(0x000711d059bc6cef, 0x0000ea1c699aeba1, 0x0006371a8052c525, 0x000699f87dd13a72,
							  0x00021319ac452786),
				FIELD_LITERAL(0x0004179c92b1b0bb, 0x00046e9ddba894d8, 0x0001e24442ec9a91, 0x0004c132a51620b3,
							  0x0006d110187f3653),
				FIELD_LITERAL(0x0004752d8b4757d6, 0x0003037d1074a2a3, 0x0003e42cfdb0ba8b, 0x0002a28dce1000aa,
							  0x00073a9ba5d3f201),
				FIELD_LITERAL(0x000605edf6ba1a36, 0x000013aba4619a54, 0x0007ad04bb3634df, 0x0007d3751dadf975,
							  0x0007857a65f3ad25),
				FIELD_LITERAL(0x0003117ab7b95c2b, 0x0000f4a313b2a63d, 0x0006eb78029227ec, 0x00043b924f138238,
							  0x00073aad45f02122),
				FIELD_LITERAL(0x0005c12191e279b9, 0x00075a9e7e4e8c5d, 0x0003a9d09d2551e0, 0x0002d7e92ba557cc,
							  0x000000a7d4499ac3),
				FIELD_LITERAL(0x0005b75a63605042, 0x0001fb3e9b1e1738, 0x00054c87b6f7d7b6, 0x0003b73e6812d3e8,
							  0x000633794ff51d12),
				FIELD_LITERAL(0x00058b7c046273ac, 0x0000464dc4a43f06, 0x0004eb0e5479c3c5, 0x00036c45d45ee21a,
							  0x00047b89a5b4d946),
				FIELD_LITERAL(0x0002c15e3b3687ba, 0x0005209d2ce7fc91, 0x0005773da0f5711a, 0x00004d96ced4966e,
							  0x0001fa8fc1035b8b),
				FIELD_LITERAL(0x00075c8cfdf08431, 0x0003e5ee1a32e561, 0x00017f242d52abcb, 0x00070b795ca26857,
							  0x0002cb36d5df0af3),
				FIELD_LITERAL(0x0006a3037380c025, 0x0005f0b9e09cee4c, 0x000333017642af74, 0x00023fd62c2cfe7a,
							  0x00070eee8fed21d2),
				FIELD_LITERAL(0x0001744e9770fe63, 0x0002635b0761a50e, 0x0001322c61f83f00, 0x00063be3797d570c,
							  0x0005afe452e6b7e9),
				FIELD_LITERAL(0x00005fff6e9b6af7, 0x0003e58a55a575a1, 0x000616d026c6eff2, 0x000186a3124f745b,
							  0x0002eec52ffe33c4),
				FIELD_LITERAL(0x0001ee0dff83b7ca, 0x00022805e31c6873, 0x0006fd7df7edeaef, 0x0002f0f61779d562,
							  0x0004deb8f2bacd10),
				FIELD_LITERAL(0x0003df7b4c0f2a59, 0x000302d0b8eb81a7, 0x0001c2717df33aff, 0x0006f3f90b3ffde9,
							  0x0003428115ee6c46),
				FIELD_LITERAL(0x0001ab77a68de949, 0x0005da9c4d9a1ae9, 0x0003ce86c23f9b7c, 0x00007c893f16e3d9,
							  0x000190c2b28c32a8),
				FIELD_LITERAL(0x0000bae92c40e17e, 0x0004a8ef7ffd05e8, 0x0005e3a63cc24e24, 0x0001ed40c1f74c12,
							  0x000258c0a1c13ff6),
				FIELD_LITERAL(0x0001674175148292, 0x00036d3d03e1f95c, 0x00049ecbbb4c9924, 0x000603782041936d,
							  0x000521d1cc84c8d6),
				FIELD_LITERAL(0x0004c7d5df621bb3, 0x00063a78ba5518cb, 0x00050af726ccf0a4, 0x0003745ad4fb4c6d,
							  0x0004b598e9a94c84),
				FIELD_LITERAL(0x000546d94d9e537c, 0x0001f783b157c7bb, 0x00034c7f212657b4, 0x0006ea763a87171a,
							  0x00074beeb5597da9),
				FIELD_LITERAL(0x00009c1897ee2bb3, 0x00022cbd1740946f, 0x00051e8f81dd639f, 0x00044423bda03112,
							  0x00025d54e5b5f216),
				FIELD_LITERAL(0x00037efe726b959f, 0x000251179afe0af9, 0x00027abb104aaf2d, 0x0000409b36a0b0c0,
							  0x0007f20165baf2eb),
				FIELD_LITERAL(0x0001e7dc70d2e455, 0x00079f1c0b114486, 0x0002b9b9c0211476, 0x000420d65df5b9c1,
							  0x0007ad32d88f4e65),
				FIELD_LITERAL(0x0000f4d9cbd1dced, 0x0000ca815a5fa452, 0x00040cdd0b2e26d2, 0x0005ab32035de1dc,
							  0x0004387b97d56e74),
				FIELD_LITERAL(0x0004282b73d9d3e6, 0x0006f6ae3911c629, 0x0007e698e17d290f, 0x000064657542456d,
							  0x00022eaf07413105),
				FIELD_LITERAL(0x0004d9e24bbb1c38, 0x00001d0b9cb4f6e6, 0x00008953dd712c89, 0x00062f9f338dc8e9,
							  0x0005b270d74b9a0b),
				FIELD_LITERAL(0x000735ad38a70d62, 0x0007c2c0047359b6, 0x00053ecc0dd53647, 0x0000fa507a3b1320,
							  0x000362d0b0c5919d),
				FIELD_LITERAL(0x0001e756ac51c2d7, 0x0002fb982df272d3, 0x0002bcba823c3ff6, 0x00000e8c28e674f5,
							  0x0001511ccec93f3e),
				FIELD_LITERAL(0x0005d9d5f3a4d0f4, 0x00014e0b6acbbb8a, 0x0004c935dce28917, 0x0004e84532fe74e9,
							  0x0003532b26c5bdd3),
				FIELD_LITERAL(0x0002c7c6bf08ea52, 0x0004ce9cf3905bbd, 0x0006eff528517cdf, 0x00051c7e30819d9f,
							  0x00078ddfe6e8eaf0),
				FIELD_LITERAL(0x00040b28295a488c, 0x00058f3942269291, 0x0002eae04529af91, 0x0005a950aa509a31,
							  0x00051d13d423f3cc),
				FIELD_LITERAL(0x00075bbfd400a649, 0x0002c84af6f7554f, 0x00010589298f1c45, 0x0002df1c4551d7a3,
							  0x00040ada606a7008),
				FIELD_LITERAL(0x0000cb4829d47de1, 0x00035279e3dcb0f4, 0x0000796e2b17fc93, 0x0000f7471379a59e,
							  0x0004cb38c4a47f2d),
				FIELD_LITERAL(0x00063d326152d536, 0x0001f0f272df8e88, 0x00020d57f1ef5f0b, 0x000049ae733cd741,
							  0x000789b0bd910484),
				FIELD_LITERAL(0x00049e000de68a33, 0x0002569532faf05e, 0x0002c360e2577651, 0x00023e58038a73d4,
							  0x0005cfd1c66aa5db),
				FIELD_LITERAL(0x0005219445517667, 0x00052a931068f3ea, 0x0006cc6f70494867, 0x00050f70ab70bd44,
							  0x0004939aea5e18ae),
				FIELD_LITERAL(0x0002a678bc8c2008, 0x0001fd399c8dcbff, 0x0006dbf73cfc616e, 0x00011a6e85d57176,
							  0x00002f713757e057),
				FIELD_LITERAL(0x0006d9cd93b1ccdc, 0x00043d4ce72bf50a, 0x0003e999e2d35c59, 0x00001ae0db65d2ee,
							  0x0007c4b601137e07),
				FIELD_LITERAL(0x0004bc6553755ebf, 0x00056e8f93c8dfe2, 0x000323b34a8ed19f, 0x000571befc514dab,
							  0x00036f0d981e9dde),
				FIELD_LITERAL(0x000787c0309c0a03, 0x0003dd7fb3241327, 0x000256b73edcaac5, 0x00071a11d2f00b44,
							  0x0000f142397f3232),
				FIELD_LITERAL(0x0006a965074f090a, 0x000042537473c8c0, 0x000479b523a03430, 0x000302e712f49521,
							  0x0001608d67c58b1d),
				FIELD_LITERAL(0x00069a9d867a02ee, 0x0006aba7c3abe71e, 0x00014af6344d6d32, 0x00059cbf2b8ec118,
							  0x00034973bd8f91f0),
				FIELD_LITERAL(0x00023c42f4d253af, 0x0000e5db7f886ed7, 0x00027c0ff78b7ca6, 0x00065a9e8c1c8eef,
							  0x000272b266b7869e),
				FIELD_LITERAL(0x00034f5086c55cc1, 0x0007caffb3de4006, 0x0007408da6d8ce8d, 0x00034209d1a9cf67,
							  0x0001e4cdc7d3366b),
				FIELD_LITERAL(0x00077be63c353577, 0x0002ccc681b95e39, 0x00037f489ba0c067, 0x000324b1d14b3c85,
							  0x000487692b3a4f7b),
				FIELD_LITERAL(0x0000bb6427577218, 0x000642b8e158c2af, 0x0005c99574a589e5, 0x00044af83be01b53,
							  0x000438f19801c19b),
				FIELD_LITERAL(0x000791929d3da811, 0x000083ba42ca3968, 0x00004f2efc6d4e98, 0x0004c09456e25204,
							  0x00038d89c4798c48),
				FIELD_LITERAL(0x000484ded8ea3977, 0x0002573a2b0d164d, 0x000057d1bd825e97, 0x00045b7f03279e7c,
							  0x00078c7feaa36f36),
				FIELD_LITERAL(0x00073ebf8e0c1412, 0x00044117b35ee64b, 0x0005d7b30a79d11e, 0x000295b447408ddb,
							  0x0006440cb28f3f89),
				FIELD_LITERAL(0x00050222af21bf22, 0x0007518c1f3d1e61, 0x00053599bee31ff1, 0x00077afb3e70937a,
							  0x00039b5cdbf90290),
				FIELD_LITERAL(0x0001f6f60a0b2349, 0x000196f840181d05, 0x0000014882eba793, 0x0000fb413162d41e,
							  0x00065dc343d01a50),
				FIELD_LITERAL(0x00007a9f75d85906, 0x000639d779f83bb4, 0x0000654c3abe3b7f, 0x000566f9422b66d3,
							  0x00044df9faded77a),
				FIELD_LITERAL(0x0001961e7e467418, 0x0000df3ccd0d527d, 0x0003d517d7c96d95, 0x000018e4481528a1,
							  0x00028b40aabc5df2),
				FIELD_LITERAL(0x0007c47eab16ee70, 0x000586b5f9af963a, 0x0007aba880ca31a5, 0x0000a08bc2d694ce,
							  0x00026acdd7701b42),
				FIELD_LITERAL(0x0000ad2aa0b6b20e, 0x000124f37a928d92, 0x00036d109f019a42, 0x0000c818e5146232,
							  0x00075d7792dfd807),
				FIELD_LITERAL(0x00030503c28b9e47, 0x0003e896b791c6fd, 0x0007fa59adcbdb16, 0x0005bf8d8a47c99e,
							  0x0006531a5de1683f),
				FIELD_LITERAL(0x0006ab691a3a6569, 0x0003dd814fc3084a, 0x0005d5c02cae4dd1, 0x0005a3c0be0f3dbe,
							  0x0006a73f5ac0a573),
				FIELD_LITERAL(0x0001d99e44acd55a, 0x0004c2f954291163, 0x0005206a8b10bb02, 0x0006c1ca2d70d6a8,
							  0x0007d8a804f96343),
				FIELD_LITERAL(0x00015b9bba5048e7, 0x000713d7a01a2316, 0x000650d90c2f5162, 0x0007a598761ff94a,
							  0x0000b72e05f1e2dc),
				FIELD_LITERAL(0x000646e1d2ecb410, 0x000629a2ef1cd6b4, 0x0006d447b257582a, 0x00079356a5148d1e,
							  0x00024a066d77bb54),
				FIELD_LITERAL(0x0006acb33791298f, 0x0000e9c707f60f66, 0x000440c5ef5f2d41, 0x0005ba193ad0b6c2,
							  0x00051456d8b751b6),
				FIELD_LITERAL(0x000181a243ee09be, 0x000488c253812ccf, 0x0003375475f6cdd3, 0x000779a477aa7ab9,
							  0x0003542890204f44),
				FIELD_LITERAL(0x0006266b7ddc99d7, 0x00026d7bf53a4cbc, 0x0001c742ceb53e2b, 0x0003e527df9f0ad1,
							  0x0006913c1028a1c2),
				FIELD_LITERAL(0x00068cca5da0b76b, 0x000669472a2d88b9, 0x00013e607a86ad68, 0x0003cb25c977181a,
							  0x0002485317d021fa),
				FIELD_LITERAL(0x00059c009c26a476, 0x00051d0584a31e4e, 0x00015fab3a664bac, 0x0003de72394f1d5e,
							  0x000531b00982956a),
				FIELD_LITERAL(0x0005deab8a4a8b2b, 0x0004ac53cff731b6, 0x0001e7ff38f7f8c4, 0x00039937580b474f,
							  0x0006fb0db141f6c6),
				FIELD_LITERAL(0x000648f2a92a9bf5, 0x000797a08ad37a50, 0x00068f6a0d3b9279, 0x00019e4b8669991a,
							  0x0003c73b04a84d00),
				FIELD_LITERAL(0x0005e149c917e591, 0x00054dbbf21fe5c9, 0x00018a9fd4f4f805, 0x0007de6e8e13e528,
							  0x00003981cea7113c),
				FIELD_LITERAL(0x0003bb66e15aee68, 0x00075ef7f4cc4a19, 0x00046c1c0f36ba47, 0x00069ac998e2c6a7,
							  0x000244eef875e3b2),
				FIELD_LITERAL(0x000711616dd6701c, 0x0001248a7f1a41d9, 0x0000819f6a28c01f, 0x0007d816d71513a4,
							  0x00043b075bc1ea59),
				FIELD_LITERAL(0x00035818217c67b2, 0x0007cc8b4ea58e8f, 0x0003946011ab16f9, 0x0002733a0aacf9e7,
							  0x00028be99e739df3),
				FIELD_LITERAL(0x00059ef24f4a8db9, 0x000250f76f1b6eae, 0x00064a73d931fa0f, 0x0000512f6d7d827e,
							  0x000607f19cbfb816),
				FIELD_LITERAL(0x000488ecf6f587f3, 0x0006aa5804295f5e, 0x0004ab3fe7880735, 0x000239212d39956a,
							  0x0003a4314607db78),
				FIELD_LITERAL(0x00056654a668e8cb, 0x00029bc320312a6b, 0x0000a956cfa8fca9, 0x0002e676e4806a32,
							  0x00002add96616e38),
				FIELD_LITERAL(0x000161d6844f4257, 0x0007a504e9fff45b, 0x0003a0a148c809fc, 0x00063db7d31212b6,
							  0x00020a34989479bc),
				FIELD_LITERAL(0x000236b2c0390d34, 0x0001a74fdf496cd3, 0x0002cc55b8b7552b, 0x0005df9eee2aa485,
							  0x0006874ffe3c2b7e),
				FIELD_LITERAL(0x0000845574316356, 0x0003780d650baa54, 0x00017cc695e858de, 0x0005aa11874d3917,
							  0x0001c1af7e47f3fd),
				FIELD_LITERAL(0x0003df29aea62b35, 0x0007d406471a4638, 0x000485f2756aae73, 0x0002fb1784f47d7b,
							  0x0006dd1a972e152c),
				FIELD_LITERAL(0x00016f1207ab7497, 0x0000062e50652318, 0x0006f768bd372106, 0x000728ab08217dc3,
							  0x0005954a56084ae3),
				FIELD_LITERAL(0x0002f4ca1559675c, 0x00019c318724c743, 0x0001919d4fc633f8, 0x0002fdfded9749ff,
							  0x000501068fe92e49),
				FIELD_LITERAL(0x000730eea5126d0b, 0x0006efb26cb70e2a, 0x00009dbb5ce158ce, 0x000454ca0f64796a,
							  0x0007c0f65d024355),
				FIELD_LITERAL(0x0003611cfe11ef4b, 0x0005aaeedb6155f0, 0x0003e540aeabe6ef, 0x0000f78b74065192,
							  0x00047523af6151bf),
				FIELD_LITERAL(0x0004f249dafd1300, 0x00032429e4917ad4, 0x000362c1b7b7f817, 0x00075447f1280d80,
							  0x000365750a59552e),
				FIELD_LITERAL(0x0005dcac2d7b940d, 0x0002b8eb45461bf5, 0x00005d0b65e115aa, 0x0000e005552b4796,
							  0x0002f003a12ebfda),
				FIELD_LITERAL(0x0000177220975d5d, 0x0005ba8842cd8e02, 0x0003c7bf472059a8, 0x00055517e31c386f,
							  0x0002c71c74d6488c),
				FIELD_LITERAL(0x00072b957911c56c, 0x0001569c007a9a12, 0x0005ba20cbbaf70c, 0x0006c3e6bdbb6099,
							  0x00064e44e81c075b),
				FIELD_LITERAL(0x00038366b3594f1e, 0x00037fe532f6ad56, 0x00021d700e67c81f, 0x0003c9049dc3bd30,
							  0x0003d151eaf6dc0e),
				FIELD_LITERAL(0x00050abcda5829d7, 0x0004609b5e96f68e, 0x00067415655ea15d, 0x0004cfb4509cc3ae,
							  0x0006b23addefb8d0),
				FIELD_LITERAL(0x000076496e346e13, 0x00036367cfa1ccd3, 0x00017e199e301bc2, 0x00070478ab91ceed,
							  0x0003045d7df7782a),
				FIELD_LITERAL(0x000137f233113b35, 0x0004ede6c0ec12a5, 0x0003701a6e67cd58, 0x0005946348005a23,
							  0x0001f7da36bbf369),
				FIELD_LITERAL(0x0007cf2d2da25631, 0x00050e34993e6b2b, 0x00077f65d18600d6, 0x0001ab10e8df75ce,
							  0x0003fb8162c6e646),
				FIELD_LITERAL(0x0002affd3fb0b8eb, 0x00038c4c5d8116e4, 0x0006c890b6236df5, 0x0001b0ca04a3dcd6,
							  0x0004ede9e2b2d222),
				FIELD_LITERAL(0x00049a95a4b4b531, 0x0003137d86fc92ec, 0x0003709d8be07c1c, 0x0004d5e3f04ed703,
							  0x0006c754f433c0f2),
				FIELD_LITERAL(0x0002af05aa5bd69d, 0x000036c6c197970a, 0x00061b671a06458f, 0x0006890eb541c3d2,
							  0x000030815bc65879),
				FIELD_LITERAL(0x0007e783c8a57961, 0x0003501cfd53edaf, 0x00060073b435c42d, 0x0003e7635150fbf5,
							  0x0001d52ce3e84f55),
				FIELD_LITERAL(0x00028af6d7e017e5, 0x00008e6916baca87, 0x0003ea1cb0f4aecd, 0x00047a27b5ebc7a2,
							  0x0003d356c5dd17f7),
				FIELD_LITERAL(0x0003e38a232359fe, 0x0001952a402660cf, 0x00026bbebb34c830, 0x0007dbc423d78448,
							  0x0000b832acb82968),
				FIELD_LITERAL(0x0004f57d66ed277b, 0x0004b8c1d3ec59de, 0x0001d02cac505cf0, 0x00004d06f0ae5d7c,
							  0x00029cf74d6d4371),
				FIELD_LITERAL(0x0006882580653583, 0x000665e9c061f2bd, 0x00065db6cc599ff2, 0x0006b8046bdafeb5,
							  0x0002ee9e3c7d3000),
				FIELD_LITERAL(0x000737e14efec8fe, 0x00022e5c3897d2b6, 0x00011a58c95c2457, 0x000780be40dda04a,
							  0x00038e16a91c29e1),
				FIELD_LITERAL(0x00017a10c6c37301, 0x0005132acffcccc4, 0x000773611bf4757c, 0x00041c2066f29f1b,
							  0x00022ea8f6d1f387),
				FIELD_LITERAL(0x000393bee768a8e8, 0x0002ce4f84e15737, 0x0001de0b0519be3c, 0x00042c68b40c0028,
							  0x000006fbc742b126),
				FIELD_LITERAL(0x0002820400093c87, 0x00070ed1de439605, 0x0001017da80352a5, 0x0001dce313d6f74f,
							  0x00041a495460a316),
				FIELD_LITERAL(0x0003390059914aa6, 0x0001dd4c7bf04d23, 0x0005a9c9d1189c6d, 0x000662ee3486ad47,
							  0x0001eb8a3c364730),
				FIELD_LITERAL(0x0007df6dea788200, 0x0002ae3f37f070c7, 0x000116afc9f98bee, 0x00050fbd7c48d713,
							  0x0001f36282673be4),
				FIELD_LITERAL(0x0002e8411e56df21, 0x000107b90a9670e3, 0x000240f904990e84, 0x0004fa5270ab1af9,
							  0x0007c2f807b6bb1f),
				FIELD_LITERAL(0x00047b6982cdef22, 0x0002aaf520c595ef, 0x0004d6dc2206f24e, 0x000380af64e1b48a,
							  0x0005c9328edeb007),
				FIELD_LITERAL(0x0003c2c334a7ef3e, 0x000400e6655a38b7, 0x000522be6814d5ae, 0x0002f23e0bc9a362,
							  0x000298daf954ed77),
				FIELD_LITERAL(0x0005f84382ee84b4, 0x0000b91f89349166, 0x00072d88b99f2ff3, 0x0005479f3f7706b4,
							  0x000035116e7285f4),
				FIELD_LITERAL(0x0006d23691a8a99d, 0x00048f42ff923c83, 0x0000e5129684bc58, 0x000630f9bc1192fd,
							  0x000401284677ede3),
				FIELD_LITERAL(0x0000eff3b8714d04, 0x000433498e2034dc, 0x00070ca8b9771326, 0x0000a264970345ad,
							  0x0007b6e44cd2dd5a),
				FIELD_LITERAL(0x000175bf84b82b29, 0x00065e0ea17de536, 0x0006b02a0010a208, 0x0000bbfa9b7e8884,
							  0x0003c21f98c815b6),
				FIELD_LITERAL(0x000679b185adb791, 0x0003ccd7cdbcb48b, 0x0001e6934282172d, 0x000112213a7ca210,
							  0x00045089bd5cfb9c),
				FIELD_LITERAL(0x0002877a97e6aec5, 0x00050083ca5fa04a, 0x0006a401497d8419, 0x0003ce63a2c47d37,
							  0x00014809d3f5339b),
				FIELD_LITERAL(0x00026e50855da5de, 0x00004d0fc457ea77, 0x0001e1f5e1f41496, 0x000175c0cd2b4571,
							  0x0001722f7954d4e2),
				FIELD_LITERAL(0x0007ac38211e7835, 0x00063d213473cbbf, 0x00005b9eada0052f, 0x0003477219f26d7f,
							  0x000453ce683f056f),
				FIELD_LITERAL(0x000726f104629123, 0x000482b184152205, 0x00054242cd088a37, 0x00032fb6be9f2837,
							  0x000734ca9dc7f7c3),
				FIELD_LITERAL(0x00062509dec41627, 0x000072099496b712, 0x0007712db0b3effb, 0x0001e9c85c77fd36,
							  0x0007f4ceff4f568c),
				FIELD_LITERAL(0x0002b1990238e0e3, 0x0006c1901505e91e, 0x00019f32cc8628f9, 0x00011218171b4b26,
							  0x0006dbdb25ce79e2),
				FIELD_LITERAL(0x0005370ef67b47ee, 0x0001580466943896, 0x0003297e2638eea5, 0x000416db4e7a73ef,
							  0x0004b3ce39e7ef57),
				FIELD_LITERAL(0x00071cc5c1b2d84d, 0x0003fa3f1fe5ba11, 0x0004520e1812cf04, 0x000612f4378d5d14,
							  0x00019041e8a9771c),
				FIELD_LITERAL(0x00037a9adac7f13d, 0x0004513446d45ac8, 0x0004862022a5e9c2, 0x00046d1fee26d322,
							  0x00050314790c0eb5),
				FIELD_LITERAL(0x00009f958ec7782b, 0x000532691db95f11, 0x0000787b85edae84, 0x0003347ccb5b1b48,
							  0x00048f02d0fe2f5f),
				FIELD_LITERAL(0x0001bd035445c3cb, 0x00020697cdb801da, 0x00027c9cd108f106, 0x0007f03792eba8ff,
							  0x000785b24c8954e8),
				FIELD_LITERAL(0x0003d9815d5b1459, 0x00079cc56b9e7bce, 0x00072c9f1a31c024, 0x00053d9b96409fbf,
							  0x0003527718dcab2f),
				FIELD_LITERAL(0x00003c0929520d8a, 0x0005b4e8fb91f6d2, 0x0003f2da27d5d5df, 0x0001c4bb87d9118d,
							  0x00026b9976202bed),
				FIELD_LITERAL(0x000395fd8480a669, 0x0001dc9000e23bd0, 0x000065404c59dfc6, 0x000125765d7383d3,
							  0x0000c7ff2cbfdb58),
				FIELD_LITERAL(0x00038f76c23acfef, 0x0005a6ffbb722028, 0x0000ce1434dbd9ba, 0x000128b22b63ce7d,
							  0x0007e28492f0e311),
				FIELD_LITERAL(0x0004ef6dec07d978, 0x0001814721d17298, 0x0002f3010824e385, 0x0004dec0df1030ea,
							  0x000732ccad416ca1)
		};
const gf_25519_t ristretto255_precomputed_wnaf_as_fe[96]
		VECTOR_ALIGNED = {
				FIELD_LITERAL(0x000642380127222b, 0x0006bdeb015cf04e, 0x0006ed75f7c2fc4f, 0x0007dc242146a194,
							  0x0003aea9a0491d17),
				FIELD_LITERAL(0x00068a94cba5aa97, 0x0002dbae983ca94a, 0x000445bd3b7036e3, 0x00068a42451fc4d1,
							  0x00011e232c83afb4),
				FIELD_LITERAL(0x00025391b7203b96, 0x000347c30d05c477, 0x0007c933299a261d, 0x00041480324ee8a6,
							  0x00064ca19224efdf),
				FIELD_LITERAL(0x0005870a7d58f0a0, 0x0001b114a243c47e, 0x00041892d3f588cf, 0x0000dd81de11287e,
							  0x00017356a5582dd5),
				FIELD_LITERAL(0x00010182955b295c, 0x00066c5c9ffd69b2, 0x00061b151a710972, 0x000283e92443fc68,
							  0x0006d37a5c5e317b),
				FIELD_LITERAL(0x00036a7b29fa190d, 0x0006935273c5f4eb, 0x00054075caf2ffbd, 0x00014270ef756d90,
							  0x000533e2a110cfc9),
				FIELD_LITERAL(0x0001629db13df925, 0x0005b8e4096d6111, 0x0003f69f6e1fa07d, 0x0000ad2fb64a4e21,
							  0x0003804eca6f1a1b),
				FIELD_LITERAL(0x00004152d30c2a52, 0x0002c24984123284, 0x00042e97ac31b344, 0x00019fefd67353e1,
							  0x0004e8cd7188a7e4),
				FIELD_LITERAL(0x00045570b5e270ed, 0x0005573633198d89, 0x0007ca223ccd5afc, 0x0007869c9de046c4,
							  0x00069e89310811bf),
				FIELD_LITERAL(0x0006d9d11e7eae02, 0x0000be17c117a8e5, 0x0005bd1bacc035a8, 0x00055263e886a24c,
							  0x0004f490d4442b45),
				FIELD_LITERAL(0x000011c8b01f8feb, 0x0007bf1c4cb192c2, 0x000326354b21cbf2, 0x000488390b6dfc94,
							  0x0005ba34838ba4de),
				FIELD_LITERAL(0x0007c67ff54be7cc, 0x0007da997c07b329, 0x00035eca964abf79, 0x000706e02cff65ab,
							  0x0007cd234d25af3c),
				FIELD_LITERAL(0x0001fb4c93b5f593, 0x0007144dc0cada1e, 0x0000d50f94b1cb97, 0x0006df9cbaf29c61,
							  0x0003edfa4c8c2b32),
				FIELD_LITERAL(0x0007271443c9ba84, 0x00016f294c6baac0, 0x00044dfa59cab659, 0x0002fe9702828a2a,
							  0x0007db9144c036dd),
				FIELD_LITERAL(0x00047163cd6e88a8, 0x0003c312ab4945e1, 0x0003021e7db7375a, 0x00055fbc7b3f6c06,
							  0x000272ecf2d95b4e),
				FIELD_LITERAL(0x00038b922c70ed29, 0x000253866fc7c488, 0x000576f12a312db9, 0x00045d4f321497af,
							  0x00018e5445d11403),
				FIELD_LITERAL(0x0003f8e7ccec15a0, 0x00052340d38e8703, 0x0001fe25f1ae8f20, 0x0003ddd469f772d0,
							  0x000462fbbea67ca2),
				FIELD_LITERAL(0x00011da13f2e0e8c, 0x0002aa8f508e1fd7, 0x000412a7c33e7f8e, 0x000350c2a112bd8f,
							  0x0003903a4aae1e31),
				FIELD_LITERAL(0x0007f9daed4a4867, 0x0002b6b4ed700133, 0x0002630bb5d53e2d, 0x00052b6f0617a8d5,
							  0x0003a71ea3b7dd75),
				FIELD_LITERAL(0x000784badf35d97a, 0x000130c033b608d3, 0x0004d1ca333b988c, 0x00046996c1106167,
							  0x00006cd17cb32faf),
				FIELD_LITERAL(0x000017f0bb6265b4, 0x0004b7b14a32f828, 0x00038355613c060b, 0x0002ff107843a525,
							  0x00067859833d0bcf),
				FIELD_LITERAL(0x0007efb1526681aa, 0x0005d3f09cc25381, 0x0005070ed313624a, 0x0007dc7c70fcf2e6,
							  0x00035f22ab001ece),
				FIELD_LITERAL(0x0001d03d7131822b, 0x00041269a071318a, 0x00066b533c7c2f0e, 0x00079eb2962ac445,
							  0x0007c84f8b7d6434),
				FIELD_LITERAL(0x0007bdf697319f65, 0x000733aeaf20753c, 0x0003e8ef6225fd72, 0x0004a5b9853164cc,
							  0x0007e0c9a1e3a2c0),
				FIELD_LITERAL(0x0000ea923f718b41, 0x0003ed3cdc5c1206, 0x0007fcd7e9778042, 0x000087a1037b0d5d,
							  0x00007a7a0abbab1c),
				FIELD_LITERAL(0x0001f75504e732eb, 0x00022ebe847278d8, 0x0007ea9ffc7568b3, 0x0005ce813453dcf8,
							  0x000487735ef97869),
				FIELD_LITERAL(0x0005724daa8d895d, 0x0000dc4fb5cda1a1, 0x0005caeaaa9fb58e, 0x0002cc7ce3532d7a,
							  0x00078cb9c16aa739),
				FIELD_LITERAL(0x000132663b80f4fb, 0x0003569bb0747910, 0x0001254f43541bae, 0x0005ef6302e41398,
							  0x0000f0739e94acdc),
				FIELD_LITERAL(0x00062c278d9a1d30, 0x000160f59d5d7ddb, 0x0003a13c02fd4a4c, 0x0003ae8e19ec0313,
							  0x0007ff33d0402d0a),
				FIELD_LITERAL(0x000779188d9101bd, 0x0003907b5e2acb57, 0x0000f2016ad328f1, 0x0002563d8843c96e,
							  0x000325477c857086),
				FIELD_LITERAL(0x0002b91f27fd54d4, 0x0006396d4db9c2ed, 0x0001910e4a18d580, 0x00013a22c5bab363,
							  0x0007a440ee553a25),
				FIELD_LITERAL(0x000490c21e746b15, 0x00024b7059991174, 0x00008ee694b74d75, 0x0005e237b7856642,
							  0x0007642c6cdb680c),
				FIELD_LITERAL(0x0005dbf419ae9d74, 0x00048e711fdf576f, 0x00075068ca732b86, 0x0006e8b996a54910,
							  0x000772260ac3718e),
				FIELD_LITERAL(0x000482565fa8a25b, 0x0003df033dcf6602, 0x00064e0f3b4e7074, 0x00021b4575c116f5,
							  0x0002208124f689de),
				FIELD_LITERAL(0x0007585a86ebfdf4, 0x0007b22f0200bb5d, 0x0004c01c0570390b, 0x00012d4f936a9ace,
							  0x0007061937f48098),
				FIELD_LITERAL(0x00058c8ef3313e8c, 0x0004fe676de9150c, 0x000071322bae837f, 0x0004719a9c643417,
							  0x0000b3d8da873b81),
				FIELD_LITERAL(0x0004a783941354c6, 0x0004a8dbae0192b1, 0x00066e6e2284eb96, 0x000328e80b25e8c3,
							  0x000042a8e76bf4d5),
				FIELD_LITERAL(0x0001d8c052051ec3, 0x000366a48a8dd65b, 0x0002a78e24295abf, 0x000129d49470f3e6,
							  0x0006c57172fbfc6f),
				FIELD_LITERAL(0x00058858b562e4d4, 0x0007aa756a9d33c0, 0x0000d5156276e848, 0x00053461aacbb1be,
							  0x000003d03c677fca),
				FIELD_LITERAL(0x0004ec9d19b70d7e, 0x0006b590207bdecd, 0x0001637d3bcc3bb3, 0x00000c22df7f92fb,
							  0x00041ea544c47cfa),
				FIELD_LITERAL(0x0005bb2c05450730, 0x000699da0443d31e, 0x00029833797938dd, 0x00047094e611ef5a,
							  0x0003a80296f5af96),
				FIELD_LITERAL(0x0001ac52918f4c8e, 0x00070d18d98c3ff4, 0x0003e5732b1553db, 0x00072df46e974e9d,
							  0x000122fb863fcfd7),
				FIELD_LITERAL(0x00000849cf428975, 0x000727067cad891a, 0x0004f88f61de7005, 0x00044257203c4bbb,
							  0x0004c637329a0014),
				FIELD_LITERAL(0x000765ea2cf96125, 0x00020be964ac2553, 0x0006542c16078fcd, 0x0007e1c9a694af26,
							  0x000670be61b828ab),
				FIELD_LITERAL(0x0003e966dcdc760c, 0x00047dd5a3cb73ac, 0x00061d635f813625, 0x0006d76efc6f57ba,
							  0x00054decaca409ff),
				FIELD_LITERAL(0x00006abffd1f9a07, 0x0006a24984b59c94, 0x00001c88b2d5ccab, 0x00078756f923d472,
							  0x000523ae194c2908),
				FIELD_LITERAL(0x000295f6aed6c95f, 0x00063835a88edc2f, 0x0000d413a8f5d2be, 0x0006d19ac30fb51e,
							  0x000209a4daa47af4),
				FIELD_LITERAL(0x0007b3d422474c11, 0x00035fd7bbd41a91, 0x00038313d567d746, 0x00044be2c7641673,
							  0x0003cfb2e79b0db4),
				FIELD_LITERAL(0x0007deb72bd44d2d, 0x000739424ef1d75e, 0x0004018d17e7a6b2, 0x0007b6e2a9d39e87,
							  0x000521ea05c6c6dd),
				FIELD_LITERAL(0x0001a5e807310023, 0x00064308e578ea3e, 0x00051e6fd6a01240, 0x000274e880dadbdd,
							  0x0001f551c726c373),
				FIELD_LITERAL(0x0004d3ce8a1f77f7, 0x0003167790f075b1, 0x0004e6bce7f4a904, 0x0004d2ccd17b0874,
							  0x0007dd01b360f566),
				FIELD_LITERAL(0x00073aa273d83a1f, 0x000509605eef38e1, 0x0002478a49a7bd9c, 0x00037b4fffcc9a8f,
							  0x0003de7bfae4d9c0),
				FIELD_LITERAL(0x00010ab29d20014a, 0x0003dad754471f37, 0x0005db76f33e4e9e, 0x000233bcc4657dd9,
							  0x00064a6db2e9a1a4),
				FIELD_LITERAL(0x00061971ac718eb9, 0x0002cedb4d83bc7c, 0x000450581aa489e6, 0x000085abee0c4ae9,
							  0x000375e304315ad9),
				FIELD_LITERAL(0x0004e69a3015eec3, 0x00014f8520f65886, 0x000603fe316ae01d, 0x000266136364ded2,
							  0x0001ca16145255d7),
				FIELD_LITERAL(0x000195b299aaa7a2, 0x00029dcb30ab6966, 0x0007db5d6559e7e8, 0x0003080db154f47f,
							  0x00039c84ee5affcf),
				FIELD_LITERAL(0x00021a432b19e270, 0x0006448861623f70, 0x0004383a5006d140, 0x000426de3a89b443,
							  0x0001296a8b73e4ab),
				FIELD_LITERAL(0x00026b6e1920377f, 0x0001fe04f05868d1, 0x00035b308dd430aa, 0x0004a38a5bd39fc2,
							  0x0007a2a54f12cec0),
				FIELD_LITERAL(0x00019031dbbe6961, 0x000228c57c496dbd, 0x00016d3b12e551b5, 0x0006f71b0487b7f1,
							  0x0000576d528efd97),
				FIELD_LITERAL(0x0006a3af1de65daa, 0x00058620d6a4624a, 0x00062c5f94e31af3, 0x00065f2be517410c,
							  0x00061ed8888aeaad),
				FIELD_LITERAL(0x000460e8ec01abc0, 0x00029d22bb6910a9, 0x0000bb5a4290fa5c, 0x000761396d21fe81,
							  0x00017529bc98149c),
				FIELD_LITERAL(0x0001a2d5558fa158, 0x00018db5df86dcda, 0x000628100de92051, 0x0002e1d2985a8b52,
							  0x0000a021ed4469e4),
				FIELD_LITERAL(0x0003c1838ccb4f06, 0x000433f163939d2f, 0x0003c45789e20d0e, 0x0004cc1dd7cf2cda,
							  0x0004a3d1db8e2fb0),
				FIELD_LITERAL(0x00078bc9fe3174f7, 0x0005463ef645ece5, 0x0005977ab88ef0f8, 0x000143fe3a6097c1,
							  0x00014e54b582e50b),
				FIELD_LITERAL(0x000297c2159dd2ea, 0x0002225918017b5d, 0x0000fd2c877e4d6d, 0x0000a876d935de03,
							  0x0003aa2b685088ec),
				FIELD_LITERAL(0x000381ec20845ff6, 0x00010287499d4119, 0x00071f5a1e12659a, 0x0007119ecc4ec7fc,
							  0x00065b686f7be346),
				FIELD_LITERAL(0x00079aa225363911, 0x0004401073991c38, 0x0002d622e1b2ab01, 0x0006d88484b2ff0e,
							  0x0001af6bad1d0067),
				FIELD_LITERAL(0x0004a9bd5d80f94a, 0x000200829b9a0578, 0x00005d3adbbe3535, 0x0004a01abc9f4d78,
							  0x000318228e347c33),
				FIELD_LITERAL(0x00078a9576d93baf, 0x0002b2a7e675aabc, 0x00077ccfec62185f, 0x00030ce0149594eb,
							  0x00079ada3764fe9e),
				FIELD_LITERAL(0x00019f03aa64e86b, 0x000524ed3ec7b93e, 0x00051dea71a325e6, 0x0006072282cc2dd1,
							  0x0003f6161300548d),
				FIELD_LITERAL(0x0003d4e4793a59c5, 0x00039088df420d66, 0x000059f2dc08ae93, 0x0002a529016f70f4,
							  0x00003d508c2008c6),
				FIELD_LITERAL(0x0000f3116a3baba1, 0x000087e19c7c7a88, 0x00064eadf2277a4f, 0x0007d9a18deea24e,
							  0x000204fcdb56e2b5),
				FIELD_LITERAL(0x000740a868c461a6, 0x00008d33fd39e939, 0x000546fc277d8361, 0x00049a29cc27b47d,
							  0x00066efe0241ab2d),
				FIELD_LITERAL(0x0004c02370cdf9e0, 0x0002753707967fe5, 0x0003e9e845537aa4, 0x00052e8412924bcd,
							  0x00035a32466d04a6),
				FIELD_LITERAL(0x00056e5f94d6709d, 0x0000baa9a44a9de5, 0x0002f96da022a0e7, 0x000522f1a31020d4,
							  0x0002c56138662fb1),
				FIELD_LITERAL(0x0003a975fed6c7ef, 0x0005be0807c70f4d, 0x00056cb1100a4f60, 0x000039e4317fae1e,
							  0x0002d3e8e7c807c5),
				FIELD_LITERAL(0x000049cd79d8153d, 0x0005f7f1bfb82d68, 0x0006329634d9cab0, 0x0007bcb505082b4e,
							  0x00053f1ca734f15f),
				FIELD_LITERAL(0x0000fdb698137903, 0x0005fb51b23a7650, 0x00056c97f01bfb0b, 0x0002c8a3ede0e6c6,
							  0x0000dffef54d46bd),
				FIELD_LITERAL(0x000023fde8f23ca3, 0x0003e79e97bcb77c, 0x0006682d0da044a2, 0x0002b5cc9caad587,
							  0x0007053a7396d844),
				FIELD_LITERAL(0x0007325e1ff6a8d7, 0x000144c86fd24546, 0x000196593acaf904, 0x000241f57ca53397,
							  0x00023e58d23dff45),
				FIELD_LITERAL(0x00066242f578274b, 0x00058a001d88f9f8, 0x00036ae87b15be37, 0x00016dbd43af7f3e,
							  0x0001ce7f64876085),
				FIELD_LITERAL(0x00015f6b0f790623, 0x0007d5b90970fb7b, 0x00045b6bd21c9701, 0x0003fbe8a13740fc,
							  0x00059a684a214173),
				FIELD_LITERAL(0x00014da626cba741, 0x000101c3468580bb, 0x0004c6fb5709eea8, 0x000354aaf860f432,
							  0x0003d9501bbcc86d),
				FIELD_LITERAL(0x0004100377e37e11, 0x0000ac48fe9245e8, 0x000098c5097111d5, 0x0000c31ff20e0c11,
							  0x0004d19f0fb6c913),
				FIELD_LITERAL(0x0007c87f12093bcc, 0x000223769c082868, 0x00074d424db97824, 0x0006d7020a556573,
							  0x0001e0afdef95d3d),
				FIELD_LITERAL(0x000201774f4281a6, 0x00040d577fbe10c0, 0x0001d96faea48a3a, 0x00019d06096a4cb9,
							  0x0000c0410e02b892),
				FIELD_LITERAL(0x0004ecdd42bcb282, 0x00036eb9f22440d6, 0x00015738bdfebe58, 0x0007da6d7cd185ed,
							  0x000114cd2ee51425),
				FIELD_LITERAL(0x00061fb7d973a125, 0x00060a3d5f860ddc, 0x00058032f5a2bae4, 0x0001ae3459e6da16,
							  0x0004d8e17bd386cb),
				FIELD_LITERAL(0x0003d4f4a0189763, 0x0002ebc953fe02a4, 0x00004d165b695009, 0x00050cba13806a99,
							  0x0000f5b62c0c84e5),
				FIELD_LITERAL(0x0006e654bfbff109, 0x0006018351bcbbe2, 0x00057964df181f22, 0x00033e0673d9cfb1,
							  0x00064efdf98a1040),
				FIELD_LITERAL(0x00073ad6128efea0, 0x0007c86bdff5a7c5, 0x0001a71115a02aff, 0x00049b3a3e67b1f4,
							  0x00033315bb103c63),
				FIELD_LITERAL(0x0006aac38a327053, 0x0005351c17ce82af, 0x0000f07d6bbd51f7, 0x00039497c5b160b1,
							  0x0001ca565d3b0b4c),
				FIELD_LITERAL(0x00030e1e990f426f, 0x0000a0a8e67aac06, 0x0005d5c4267d1f6c, 0x00051b0ebc5614b8,
							  0x0000ca37a6b5f563),
				FIELD_LITERAL(0x00009dcbfce95c17, 0x0001ea312e0ecf1f, 0x0001bfaafa617fde, 0x00017565626471ce,
							  0x00057a7e865a0896),
				FIELD_LITERAL(0x00036e4ca4b09fec, 0x00070559d5d9b147, 0x00035855772927b5, 0x000651fbdadbcd73,
							  0x0007aea9eb02eba1),
				FIELD_LITERAL(0x000447db14883a00, 0x0002ccbdfcdd06ca, 0x00052ae17d38e284, 0x0002d754ce20339c,
							  0x000163594fcc2603)
		};
