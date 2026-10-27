(function(){
  var out=[];function log(k,v){out.push(k+"="+JSON.stringify(v))}
  function visible(t){return Array.from(t.tBodies[0].rows).filter(function(r){return !r.hidden}).map(function(r){return r.cells[0].textContent})}
  try{
  var t=document.querySelector("table.xf");var status=document.querySelector('[data-status="'+t.id+'"]');
  log("initial_status",status.textContent);
  var cols=Array.from(t.tHead.rows[0].cells).map(function(th){return th.getAttribute("data-col")});
  log("cols",cols);
  // open filter on "membership"
  var c=cols.indexOf("membership");var btn=t.tHead.rows[0].cells[c].querySelector(".xf-btn");btn.click();
  var pop=document.querySelector(".xf-pop");log("pop_open",!pop.hidden);
  log("values",Array.from(pop.querySelectorAll(".xf-list label")).map(function(l){return l.textContent}));
  // uncheck "direct"
  Array.from(pop.querySelectorAll(".xf-list label")).forEach(function(l){if(l.textContent.indexOf("direct")===0){var cb=l.querySelector("input");cb.checked=false;cb.dispatchEvent(new Event("change"))}});
  log("selectall_indeterminate",pop.querySelector(".xf-all input").indeterminate);
  Array.from(pop.querySelectorAll(".xf-actions button")).filter(function(b){return b.textContent==="OK"})[0].click();
  log("after_membership_filter",visible(t));log("status",status.textContent);log("pop_closed",pop.hidden);
  log("header_on",t.tHead.rows[0].cells[c].classList.contains("xf-on"));
  // second filter on "via groups" (multi-valued): open and see counts reflect first filter
  var v=cols.indexOf("via groups");t.tHead.rows[0].cells[v].querySelector(".xf-btn").click();
  log("via_values",Array.from(pop.querySelectorAll(".xf-list label")).map(function(l){return l.textContent}));
  // search box in popover narrows and OK selects only search results
  var s=pop.querySelector("input[type=search]");s.value="eng";s.dispatchEvent(new Event("input"));
  log("via_search",Array.from(pop.querySelectorAll(".xf-list label")).map(function(l){return l.textContent}));
  Array.from(pop.querySelectorAll(".xf-actions button")).filter(function(b){return b.textContent==="OK"})[0].click();
  log("after_two_filters",visible(t));
  // sort Z->A on name via popover
  var n=cols.indexOf("name");t.tHead.rows[0].cells[n].querySelector(".xf-btn").click();
  Array.from(pop.querySelectorAll(".xf-sort button"))[1].click();
  log("sorted_desc_aria",t.tHead.rows[0].cells[n].getAttribute("aria-sort"));
  // clear all
  document.querySelector('[data-clear="'+t.id+'"]').click();
  log("after_clear",visible(t));log("clear_hidden",document.querySelector('[data-clear="'+t.id+'"]').hidden);
  // quick search
  var q=document.querySelector('input[data-filter="'+t.id+'"]');q.value="staff";q.dispatchEvent(new Event("input"));
  log("quick",visible(t));
  // XSS check: no script injected beyond ours
  log("scripts",document.scripts.length);
  // tree
  var tree=document.getElementById("tree");
  if(tree){log("tree_details",tree.querySelectorAll("details").length);
    document.querySelector('[data-tree-action="collapse"]').click();log("tree_open_after_collapse",tree.querySelectorAll("details[open]").length);
    document.querySelector('[data-tree-action="expand"]').click();log("tree_open_after_expand",tree.querySelectorAll("details[open]").length);
    log("tree_text",tree.textContent.replace(/\s+/g," ").trim())}
  }catch(e){log("ERROR",String(e)+" "+e.stack)}
  var pre=document.createElement("pre");pre.id="harness";pre.textContent=out.join("\n");document.body.appendChild(pre);
})();
