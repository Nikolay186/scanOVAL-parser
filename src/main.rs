use scraper::{Html, Selector};
use std::io::{BufRead, BufReader};
use std::{
    fs::{self, File},
    io::Write,
};

fn main() {
    let bdu_codes = parse_report();
    let mut result = get_vuln_list(bdu_codes);

    get_capecs(&mut result);

    print(result);
}

fn get_vuln_list(bdu_codes: Vec<String>) -> Vec<Vec<String>> {
    let vuln_file = File::open("vulnlist.csv")
        .expect("Cannot open vuln file");
    let reader = BufReader::new(vuln_file);
    let mut result = vec![];

    let data: Vec<Vec<String>> = reader
        .lines()
        .map(|line| {
            line.unwrap()
                .split(";")
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();

    for code in bdu_codes {
        for record in &data {
            if record[0].contains(&code) {
                let cve = match record[1].split_once(',') {
                    Some(record) => record.0.split_once('-').unwrap().1.to_owned(),
                    _ => record[1].split_once('-').unwrap().1.to_owned(),
                };
                let cwe = record[2]
                    .split(',')
                    .map(|cwe| {
                        if !cwe.is_empty() {
                            let mut cwe = cwe.split_once('-').unwrap().1.to_owned();
                            cwe.push(',');
                            cwe
                        } else {
                            String::from("")
                        }
                    })
                    .collect::<String>();

                result.push(Vec::from([
                    record[0].to_owned(),
                    cve,
                    cwe.trim_end_matches(',').to_owned(),
                ]));
                break;
            }
        }
    }

    result
}

fn parse_report() -> Vec<String> {
    let report = fs::read_to_string("report.html").unwrap();
    let html = Html::parse_fragment(&report);
    let mut bdu_codes = vec![];

    let bdu_selector = Selector::parse(r#"td[class="bdu"]"#).unwrap();
    let cells = html.select(&bdu_selector).map(|bdu| bdu.inner_html());

    for cell in cells {
        for bdu in cell.split("<br>") {
            let code = bdu.split_once(':').unwrap().1;
            bdu_codes.push(code.to_owned());
        }
    }

    bdu_codes
}

fn get_capecs(codes: &mut Vec<Vec<String>>) -> Vec<Vec<String>> {
    let res: Vec<Vec<String>> = vec![];

    let reader =
        BufReader::new(File::open("cwe.csv").unwrap());
    let lines = reader.lines().map(|line| {
        line.unwrap()
            .split(';')
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    let cwe_capecs: Vec<_> = lines.collect();

    let reader =
        BufReader::new(File::open("capec.csv").unwrap());
    let lines = reader.lines().map(|line| {
        line.unwrap()
            .split(',')
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    let capec_csv: Vec<_> = lines.collect();

    // row[3] - High, row[4] - Medium, row[5] - Low, row[6] - Zero
    for row in codes {
        row.append(&mut vec!["".to_string(); 4]);
        let cwe = &row[2];
        let cwe_capec = cwe_capecs
            .iter()
            .find(|capec| &capec[0] == cwe)
            .unwrap_or(&vec![String::from(""), String::from("")])[1]
            .to_owned();
        // println!("{idx}");
        if cwe_capec.is_empty() {
            row[3] = "-".to_owned();
        } else {
            let capecs = cwe_capec
                .split(',')
                .map(|str| str.trim().to_owned())
                .collect::<Vec<String>>();
            parse_capecs(capecs, capec_csv.clone(), row);
        }
    }

    res
}

fn parse_capecs(capecs: Vec<String>, capecs_csv: Vec<Vec<String>>, row: &mut Vec<String>) {
    for capec in capecs {
        let grade = capecs_csv.iter().find(|c| &c[0] == &capec).unwrap()[1].as_str();
        match grade {
            "High" => row[3].push_str(&format!("{capec}, ")),
            "Medium" => row[4].push_str(&format!("{capec}, ")),
            "Low" => row[5].push_str(&format!("{capec}, ")),
            "Zero" => row[6].push_str(&format!("{capec}, ")),
            _ => (),
        };
    }
}

fn print(table: Vec<Vec<String>>) {
    let mut output = File::create("result.csv").unwrap();
    writeln!(output, "BDU\tCVE\tCWE\tHigh\tMedium\tLow\tZero");
    for row in table {
        writeln!(
            output,
            "{bdu}\t{cve}\t{cwe}\t{h}\t{m}\t{l}\t{z}",
            bdu = row[0],
            cve = row[1],
            cwe = row[2],
            h = row[3],
            m = row[4],
            l = row[5],
            z = row[6],
        );
    }
}