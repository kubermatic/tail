# Tail

A very simple app to display logs generated by [Prow](https://github.com/kubernetes/test-infra/tree/master/prow)

## Usage

1. Edit `manifest.yaml` to contain the bucket you use and a valid serviceAccountKey to access that bucket
1. Run `kubectl apply -f manifest.yaml`
1. Add a line like this to your prows `config.yaml` in the `plank` section: `job_url_template: 'https://prow.mycompany.com/logs/{{.Spec.Refs.Org}}_{{.Spec.Refs.Repo}}/{{with index .Spec.Refs.Pulls 0}}{{.Number}}{{end}}/{{.Spec.Job}}/{{.Status.BuildID}}'`