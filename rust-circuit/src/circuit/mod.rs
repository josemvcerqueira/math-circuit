use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::{
    ns,
    r1cs::{self, ConstraintSynthesizer, ConstraintSystemRef},
};
use ark_serialize::CanonicalSerialize;

#[derive(Debug, Clone)]
pub struct Circuit {
    // Public Inputs
    pub c: Fr,

    // Private inputs
    pub a: Fr,
    pub b: Fr,
    //
}

impl Circuit {
    /// Creates an empty circuit with all values set to zero.
    /// Used for setup phase and testing.
    pub fn empty() -> Self {
        Self {
            c: Fr::ZERO,
            a: Fr::ZERO,
            b: Fr::ZERO,
        }
    }

    /// Creates a new circuit with validation.
    ///
    /// # Errors
    /// Returns error if:
    /// - Path indices exceed tree capacity (>= 2^LEVEL)
    #[allow(clippy::too_many_arguments)]
    pub fn new(c: Fr, a: Fr, b: Fr) -> anyhow::Result<Self> {
        Ok(Self { c, a, b })
    }

    pub fn get_public_inputs(&self) -> Vec<Fr> {
        vec![self.c]
    }

    pub fn get_public_inputs_serialized(&self) -> anyhow::Result<Vec<u8>> {
        let public_inputs = self.get_public_inputs();
        let mut serialized = Vec::new();
        for input in &public_inputs {
            input
                .serialize_compressed(&mut serialized)
                .map_err(|e| anyhow::anyhow!("Failed to serialize public input: {}", e))?;
        }
        Ok(serialized)
    }
}

impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> r1cs::Result<()> {
        let c = FpVar::new_input(ns!(cs, "c"), || Ok(self.c))?;

        // Private inputs
        let a = FpVar::new_witness(ns!(cs, "a"), || Ok(self.a))?;
        let b = FpVar::new_witness(ns!(cs, "b"), || Ok(self.b))?;

        c.enforce_equal(&(a * b))?;

        Ok(())
    }
}
