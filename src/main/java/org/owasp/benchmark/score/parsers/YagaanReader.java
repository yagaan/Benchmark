package org.owasp.benchmark.score.parsers;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;

import org.owasp.benchmark.score.BenchmarkScore;

import com.yagaan.report.io.ScanIO;
import com.yagaan.report.model.Fragment;
import com.yagaan.report.model.Issue;
import com.yagaan.report.model.Scan;

public class YagaanReader extends Reader {

	public TestResults parse(final File f) throws Exception {
		final TestResults tr = new TestResults("YAG Scanner", false, TestResults.ToolType.SAST);
		tr.setTime(f);

		try (InputStream input = new FileInputStream(f)) {

			ScanIO.consume(input, new Consumer<Scan>() {

				@Override
				public void accept(final Scan t) {
					// TODO Auto-generated method stub

				}
			}, new Consumer<Issue>() {

				@Override
				public void accept(final Issue issue) {
					final int cwe = figureCWE(issue.getName());
					if (cwe > 0) {
						final Fragment location = issue.getLocation();
						final Path path = Paths.get(location.getFile());
						final String fileName = path.getFileName().toString();
						if (fileName.startsWith(BenchmarkScore.BENCHMARKTESTNAME)) {

							final String testNumberAsString = fileName
									.substring(BenchmarkScore.BENCHMARKTESTNAME.length()).replace(".java", "");

							try {
								final int testCaseNumber = Integer.parseInt(testNumberAsString);
								if (testCaseNumber >= 0) {
									final TestCaseResult tcr = new TestCaseResult();

									tcr.setNumber(testCaseNumber);
									tcr.setCategory(issue.getName());
									tcr.setCWE(cwe);

									tr.put(tcr);
								}
							} catch (final NumberFormatException e) {
								System.out.println("YagaanReader.parse()");
							}
						}

					}

				}
			});

		}

		return tr;
	}

	private static int figureCWE(final String problemTypeId) {
		switch (problemTypeId) {
		case "YAG-Scanner-java:yagaan.java_injection.cmd":
			return 78;

		case "YAG-Scanner-java:yagaan.java_encryption.weak":
			return 327;

		case "YAG-Scanner-java:yagaan.java_hash.weak":
			return 328;

		case "YAG-Scanner-java:yagaan.java_injection.ldap":
			return 90;

		case "YAG-Scanner-java:yagaan.java_injection.path":
			return 22;

		case "YAG-Scanner-java:yagaan.java_cookies.insecure":
			return 614;

		case "YAG-Scanner-java:yagaan.java_sql.injection":
			return 89;

		case "YAG-Scanner-java:yagaan.java_trust.violation":
			return 501;

		case "YAG-Scanner-java:yagaan.java_random.weak":
			return 330;

		case "YAG-Scanner-java:yagaan.java_injection.xpath":
			return 643;

		case "YAG-Scanner-java:yagaan.java_xss":
		case "YAG-Scanner-java:yagaan.java_xss.stored":
			return 79;

		default:
			// Dummy.
			return 0;
		}
	}
}
