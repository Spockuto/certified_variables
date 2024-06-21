import CertifiedData "mo:base/CertifiedData";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";
import CertTree "mo:ic-certification/CertTree";
import CV "mo:cbor/Value";
import CborEncoder "mo:cbor/Encoder";
import CborDecoder "mo:cbor/Decoder";

actor CertifiedVariable {

  type User = {
    name : Text;
    age : Nat8;
  };

  type CertifiedUser = {
    user : User;
    certificate : Blob;
    witness : Blob;
  };

  stable var count : Nat64 = 0;
  stable let cert_store : CertTree.Store = CertTree.newStore();
  let ct = CertTree.Ops(cert_store);

  public func set_user(user : User) : async Nat64 {
    count += 1;
    let path : [Blob] = [Text.encodeUtf8("user"), blobOfNat64(count)];
    ct.put(path, encodeUser(user));
    ct.setCertifiedData();
    return count;
  };

  public query func get_user(index : Nat64) : async CertifiedUser {
    let certificate = switch (CertifiedData.getCertificate()) {
      case (?certificate) {
        certificate;
      };
      case (null) {
        Debug.trap("Certified data not set");
      };
    };

    let path : [Blob] = [Text.encodeUtf8("user"), blobOfNat64(index)];

    let value = switch (ct.lookup(path)) {
      case (?value) {
        value;
      };
      case (null) {
        Debug.trap("Lookup failed");
      };
    };

    let user : User = decodeUser(value);
    let witness = ct.encodeWitness(ct.reveal(path));

    let certifiedUser : CertifiedUser = {
      certificate = certificate;
      witness = witness;
      user = user;
    };

    return certifiedUser;
  };

  func encodeUser(user : User) : Blob {
    let bytes : CV.Value = #majorType5([
      (#majorType3("name"), #majorType3(user.name)),
      (#majorType3("age"), #majorType0(Nat64.fromNat(Nat8.toNat(user.age)))),
    ]);

    let #ok(encoded_user) = CborEncoder.encode(bytes);
    return Blob.fromArray(encoded_user);
  };

  func decodeUser(bytes : Blob) : User {
    let #ok(#majorType5(map)) = CborDecoder.decode(bytes);
    let name_tag = Array.find<(CV.Value, CV.Value)>(map, func x = x.0 == #majorType3("name"));
    let age_tag = Array.find<(CV.Value, CV.Value)>(map, func x = x.0 == #majorType3("age"));

    let name = switch (name_tag) {
      case (?name_value) {
        let #majorType3(name) = name_value.1;
        name;
      };
      case (null) {
        Debug.trap("Decoding failed for name");
      };
    };

    let age = switch (age_tag) {
      case (?age_value) {
        let #majorType0(age) = age_value.1;
        Nat8.fromNat(Nat64.toNat(age));
      };
      case (null) {
        Debug.trap("Decoding failed for age");
      };
    };

    return {
      name = name;
      age = age;
    };
  };

  func blobOfNat64(n : Nat64) : Blob {
    let byteMask : Nat64 = 0xff;
    func byte(x : Nat64) : Nat8 {
      Nat8.fromNat(Nat64.toNat(x));
    };
    Blob.fromArray([
      byte(((byteMask << 56) & n) >> 56),
      byte(((byteMask << 48) & n) >> 48),
      byte(((byteMask << 40) & n) >> 40),
      byte(((byteMask << 32) & n) >> 32),
      byte(((byteMask << 24) & n) >> 24),
      byte(((byteMask << 16) & n) >> 16),
      byte(((byteMask << 8) & n) >> 8),
      byte(((byteMask << 0) & n) >> 0),
    ]);
  };

};
