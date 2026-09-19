/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::time::SystemTime;

pub trait BuilderExt {
    fn resource(self, name: &str) -> Self;
    fn check_resource(self, name: &str) -> Self;
    fn check_resource_prefix(self, prefix: &str) -> Self;
    fn check_resource_suffix(self, suffix: &str) -> Self;
    fn operation(self, name: &str) -> Self;
    fn check_operation(self, name: &str) -> Self;
    fn check_expiration_date(self, date: SystemTime) -> Self;
}

pub trait AuthorizerExt {
    fn allow_all(self) -> Self;
    fn deny_all(self) -> Self;
}
