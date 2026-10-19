//! The route tables: which rule applies to which operation of the pdns API, one table per
//! permission.
//!
//! Keep the matches exhaustive (no `_` arm), so a new route forces a decision.

use crate::pdns::Route;
use crate::policy::rule::Rule;
use crate::policy::{BodyCheck, ResponseFilter};

impl Rule {
    /// full access to the zone
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn owner(route: &Route) -> Self {
        match route {
            Route::ListApiVersions | Route::ListServers | Route::GetServer { .. } => Self::Open,

            Route::ListZones { .. } => Self::FilteredList(ResponseFilter::ZoneList),
            Route::CreateZone { .. } => Self::Body(BodyCheck::CreateZone),

            Route::GetZone { .. }
            | Route::DeleteZone { .. }
            | Route::ExportZone { .. }
            | Route::NotifyZone { .. }
            | Route::RectifyZone { .. }
            | Route::PatchZone { .. } => Self::Zone,

            Route::PutZone { .. } => Self::ZoneAndBody(BodyCheck::PutZone),

            Route::ListAutoprimaries { .. }
            | Route::CreateAutoprimary { .. }
            | Route::DeleteAutoprimary { .. }
            | Route::FlushCache { .. }
            | Route::GetConfig { .. }
            | Route::ListNetworks { .. }
            | Route::GetNetwork { .. }
            | Route::SetNetwork { .. }
            | Route::SearchData { .. }
            | Route::GetStatistics { .. }
            | Route::ListTsigKeys { .. }
            | Route::CreateTsigKey { .. }
            | Route::GetTsigKey { .. }
            | Route::PutTsigKey { .. }
            | Route::DeleteTsigKey { .. }
            | Route::ListViews { .. }
            | Route::ListView { .. }
            | Route::AddToView { .. }
            | Route::DeleteFromView { .. }
            | Route::AxfrRetrieve { .. }
            | Route::ListCryptokeys { .. }
            | Route::CreateCryptokey { .. }
            | Route::GetCryptokey { .. }
            | Route::ModifyCryptokey { .. }
            | Route::DeleteCryptokey { .. }
            | Route::ListMetadata { .. }
            | Route::CreateMetadata { .. }
            | Route::GetMetadata { .. }
            | Route::ModifyMetadata { .. }
            | Route::DeleteMetadata { .. } => Self::Never,
        }
    }

    /// solve ACME DNS-01 challenges: what clients like lego and acme.sh need, i.e.
    /// finding the zone, reading and changing the challenge records and notifying secondaries
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn acme(route: &Route) -> Self {
        match route {
            Route::ListApiVersions | Route::ListServers | Route::GetServer { .. } => Self::Open,

            Route::ListZones { .. } => Self::FilteredList(ResponseFilter::ZoneList),
            Route::GetZone { .. } => Self::ZoneAndFilter(ResponseFilter::AcmeRrsets),
            Route::PatchZone { .. } => Self::ZoneAndBody(BodyCheck::AcmeRrsets),
            Route::NotifyZone { .. } => Self::Zone,

            Route::CreateZone { .. }
            | Route::PutZone { .. }
            | Route::DeleteZone { .. }
            | Route::ExportZone { .. }
            | Route::RectifyZone { .. }
            | Route::ListAutoprimaries { .. }
            | Route::CreateAutoprimary { .. }
            | Route::DeleteAutoprimary { .. }
            | Route::FlushCache { .. }
            | Route::GetConfig { .. }
            | Route::ListNetworks { .. }
            | Route::GetNetwork { .. }
            | Route::SetNetwork { .. }
            | Route::SearchData { .. }
            | Route::GetStatistics { .. }
            | Route::ListTsigKeys { .. }
            | Route::CreateTsigKey { .. }
            | Route::GetTsigKey { .. }
            | Route::PutTsigKey { .. }
            | Route::DeleteTsigKey { .. }
            | Route::ListViews { .. }
            | Route::ListView { .. }
            | Route::AddToView { .. }
            | Route::DeleteFromView { .. }
            | Route::AxfrRetrieve { .. }
            | Route::ListCryptokeys { .. }
            | Route::CreateCryptokey { .. }
            | Route::GetCryptokey { .. }
            | Route::ModifyCryptokey { .. }
            | Route::DeleteCryptokey { .. }
            | Route::ListMetadata { .. }
            | Route::CreateMetadata { .. }
            | Route::GetMetadata { .. }
            | Route::ModifyMetadata { .. }
            | Route::DeleteMetadata { .. } => Self::Never,
        }
    }
}
