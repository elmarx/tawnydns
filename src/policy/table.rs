//! The route table: which rule applies to which operation of the pdns API.

use crate::pdns::Route;
use crate::policy::rule::Rule;
use crate::policy::{BodyCheck, ResponseFilter};

impl From<&Route> for Rule {
    /// Keep this match exhaustive (no `_` arm), so a new route forces a decision.
    #[deny(clippy::wildcard_enum_match_arm)]
    fn from(route: &Route) -> Self {
        match route {
            Route::ListServers | Route::GetServer { .. } => Self::Open,

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
}
