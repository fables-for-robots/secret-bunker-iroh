use kube::CustomResourceExt;

fn main() {
    print!(
        "{}",
        serde_yaml::to_string(&secret_bunker_operator::crd::BunkerSecret::crd()).unwrap()
    );
}
