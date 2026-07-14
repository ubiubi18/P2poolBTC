use crate::{
    package_dag_cbor, validate_governance_parameters, verify_dag_cbor_car, DagCborPackage,
    GovernanceError, GovernanceParameterSetV1, SourceError,
};
use thiserror::Error;

pub type GovernanceParameterPackage = DagCborPackage<GovernanceParameterSetV1>;

#[derive(Debug, Error)]
pub enum GovernanceParameterError {
    #[error(transparent)]
    Governance(#[from] GovernanceError),
    #[error(transparent)]
    Source(#[from] SourceError),
}

pub fn package_governance_parameters(
    parameters: GovernanceParameterSetV1,
) -> Result<GovernanceParameterPackage, GovernanceParameterError> {
    validate_governance_parameters(&parameters)?;
    Ok(package_dag_cbor(parameters)?)
}

pub fn verify_governance_parameters_car(
    bytes: &[u8],
) -> Result<GovernanceParameterPackage, GovernanceParameterError> {
    let package: GovernanceParameterPackage = verify_dag_cbor_car(bytes)?;
    validate_governance_parameters(&package.value)?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_package_round_trips_and_rejects_formula_changes() {
        let parameters = GovernanceParameterSetV1::experimental_defaults();
        let package = package_governance_parameters(parameters.clone()).unwrap();
        let verified = verify_governance_parameters_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);
        assert_eq!(verified.value, parameters);

        let mut invalid = parameters;
        invalid.status_bps.newbie = 7_001;
        assert!(package_governance_parameters(invalid).is_err());
    }
}
