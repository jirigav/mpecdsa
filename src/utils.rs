/*
Copyright 2021

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use curv::elliptic::curves::p256::{FE, GE};
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;


/*
check validity of ECDSA signature on the P256 curve
*/
#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: String, pk: &GE) {
    use p256::ecdsa::Signature;
    use p256::ecdsa::{VerifyKey, signature::Verifier};

    let public_key : VerifyKey = pk.get_element();
    let signature : Signature = Signature::from_scalars(r.get_element(), s.get_element()).unwrap();


    let is_correct = public_key.verify(msg.as_bytes(), &signature).is_ok();
    assert!(is_correct);

}
