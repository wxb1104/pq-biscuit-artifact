/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
fn main() {
    println!("cargo:rerun-if-changed=src/format/schema.proto");
    //prost_build::compile_protos(&["src/format/schema.proto"], &["src/"]).unwrap();
}
