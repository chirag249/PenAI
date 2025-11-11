import json, os

class Reporter:
    @staticmethod
    def write_reports(outdir, meta, findings):
        os.makedirs(f"{outdir}/reports", exist_ok=True)
        with open(f"{outdir}/reports/final_report.json","w") as f:
            json.dump({"meta":meta,"findings":findings}, f, indent=2)
        with open(f"{outdir}/reports/final_report.txt","w") as f:
            f.write("Final report\n")
            f.write("Meta:\n")
            f.write(json.dumps(meta, indent=2))
            f.write("\nFindings:\n")
            for item in findings:
                f.write(json.dumps(item, indent=2))
                f.write("\n\n")
