<?php
// ============================================================
//  VulnBank – Investment Calculator (AngularJS)
//  CWE-94: Client-Side Template Injection (CSTI)
//
//  Server-side output escaping is applied (htmlspecialchars),
//  but the value is inserted into an AngularJS template scope.
//  AngularJS EVALUATES {{...}} expressions AFTER HTML rendering,
//  bypassing server-side output encoding.
//
//  Payload: {{constructor.constructor('alert(document.cookie)')()}}
//  AngularJS 1.x sandbox bypass: {{a=['constructor'];a[a]()[a[a]()]('alert(1)')()}}
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// Server-side encoding is applied — but CSTI bypasses it via AngularJS evaluation
$name = htmlspecialchars($_GET['name'] ?? 'Investor');  // looks safe, but isn't
?>

<!-- CWE-94: Outdated AngularJS 1.6.9 loaded — known CSTI and sandbox bypasses -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.9/angular.min.js"></script>

<!-- ng-app scope: AngularJS evaluates {{expressions}} in the DOM -->
<div ng-app="vulnCalc" ng-controller="CalcCtrl" class="mt-2">

<div class="alert-vuln">
  ⚠️ <span class="badge-vuln">CWE-94 CSTI</span> — AngularJS evaluates <code>{{expressions}}</code> after server-side htmlspecialchars, bypassing output encoding
</div>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="card shadow mb-3">
      <div class="card-header">Investment Calculator</div>
      <div class="card-body">

        <!-- CWE-94: $name is htmlspecialchars'd on server but AngularJS evaluates it client-side -->
        <!-- Try: ?name={{7*7}} to test, then ?name={{constructor.constructor('alert(document.cookie)')()}} -->
        <h5>Welcome, <?= $name ?>!</h5>
        <p class="text-muted vuln-label">↑ Server applied htmlspecialchars(), but AngularJS evaluates {{ }} after rendering</p>

        <div class="row mb-3 mt-3">
          <div class="col">
            <label>Principal ($)</label>
            <input type="number" ng-model="principal" class="form-control" value="10000">
          </div>
          <div class="col">
            <label>Annual Rate (%)</label>
            <input type="number" ng-model="rate" class="form-control" value="5">
          </div>
          <div class="col">
            <label>Years</label>
            <input type="number" ng-model="years" class="form-control" value="10">
          </div>
        </div>

        <div class="p-3 bg-light rounded">
          <strong>Future Value:</strong>
          <span class="balance-hero">${{(principal * Math.pow(1 + rate/100, years)) | number:2}}</span><br>
          <strong>Interest Earned:</strong>
          ${{((principal * Math.pow(1 + rate/100, years)) - principal) | number:2}}
        </div>

      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Try CSTI Injection</div>
      <div class="card-body">
        <p style="font-size:.85rem">The <code>?name=</code> parameter is passed to AngularJS scope via the server-rendered value. Even though the server applies <code>htmlspecialchars()</code>, AngularJS evaluates the expression after HTML parsing.</p>

        <div class="list-group mb-2">
          <a href="csti.php?name={{7*7}}" class="list-group-item list-group-item-action py-1" style="font-size:.85rem">
            <code>?name={{7*7}}</code> — math expression test (should show 49)
          </a>
          <a href="csti.php?name={{constructor.constructor('alert(document.cookie)')()}}"
             class="list-group-item list-group-item-action py-1" style="font-size:.85rem">
            <code>?name={{constructor.constructor('alert(document.cookie)')()}}</code> — cookie theft
          </a>
          <a href="csti.php?name={{$on.constructor('alert(1)')()}}"
             class="list-group-item list-group-item-action py-1" style="font-size:.85rem">
            <code>?name={{$on.constructor('alert(1)')()}}</code> — AngularJS 1.x sandbox bypass
          </a>
        </div>
        <small class="text-muted">Click a link above to inject into the Welcome message.</small>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>Why htmlspecialchars doesn't help here:</strong><br>
        Server outputs: <code>&lt;h5&gt;Welcome, {{7*7}}!&lt;/h5&gt;</code><br>
        AngularJS THEN processes the DOM and evaluates <code>{{7*7}}</code> → <code>49</code>.<br>
        Output encoding happens before AngularJS runs — it only protects against HTML injection, not template injection.<br><br>
        <strong>Stored CSTI:</strong> If any stored field (bio, transaction description) is rendered inside an <code>ng-app</code> scope, stored payloads will execute for every user who views the page.
      </div>
    </div>
  </div>
</div>

<script>
angular.module('vulnCalc', []).controller('CalcCtrl', function($scope) {
    $scope.principal = 10000;
    $scope.rate      = 5;
    $scope.years     = 10;
    $scope.Math      = Math; // expose Math to template
});
</script>

</div><!-- /ng-app -->

<?php require '_footer.php'; ?>
