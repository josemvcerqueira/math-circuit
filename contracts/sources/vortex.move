module vortex::vortex;

use sui::{bcs, groth16::{Self, Curve, PreparedVerifyingKey}};

// === Constants ===

const BN254_FIELD_MODULUS: u256 =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

// === Structs ===

public struct Vortex has key {
    id: UID,
    curve: Curve,
    vk: PreparedVerifyingKey,
}

// === Initializer ===

fun init(ctx: &mut TxContext) {
    let curve = groth16::bn254();

    let vortex = Vortex {
        id: object::new(ctx),
        vk: groth16::prepare_verifying_key(&curve, &vortex::vortex_constants::verifying_key!()),
        curve,
    };

    transfer::share_object(vortex);
}

// === Mutative Functions ===

public fun transact(self: &mut Vortex, proof_points: vector<u8>, ctx: &mut TxContext) {
    let recipient_field = bcs::to_bytes(&(ctx.sender().to_u256() / BN254_FIELD_MODULUS));
    assert!(
        self
            .curve
            .verify_groth16_proof(
                &self.vk,
                &groth16::public_proof_inputs_from_bytes(recipient_field),
                &groth16::proof_points_from_bytes(proof_points),
            ),
        0,
    );
}
