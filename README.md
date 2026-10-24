# Petrol Pump Manager: server

Node.js + SQLite backend with logins (owner, manager, worker), shared business data, and a worker screen that posts credit sales straight into the customer ledger.

- `server.js`: the whole backend (one file)
- `public/index.html`: the app (ledger, stock and shop sales, suppliers, book, reports, backup, team, worker screen)
- `data.db`: created on first run; this is all your data

## Roles

| Role | Can do |
|---|---|
| Owner | Everything: Pump setup, Salary, Team (managers, accountants, and workers), approving the business day |
| Manager | Assigns duties, reviews and closes them, closes the business day, daily summary, ledger, stock and shop sales, suppliers, tanks, reports. Can add and manage workers in Team. No Pump setup, no Salary |
| Accountant | Financial oversight: Ledger, Cash flow, Books, Expenses, Day reports, Salary register & reports, Reconcile, ATG & tank registers. Read-only for duties and pump configuration |
| Worker | Their assigned duty, credit sales, tank dips, and their own pay. Can open the full detail of their past duties |

Worker credit sales appear in the customer ledger immediately. If a sale is over the customer's available credit, it is held as "waiting for approval" instead. Managers and the owner see it at the top of the Ledger tab and can approve it (it then posts to the ledger) or reject it. The worker sees the status on their screen.

## Architecture & Multi-Tenancy Scope

This system is deliberately architected for **single-pump (single-station) operation**:
- A single SQLite database (`data.db`) holds the station's nozzles, tanks, credit ledger, duties, day closures, and staff.
- Business configuration (state table row with ID 1) contains single station parameters (tanks, nozzles, rates, modes).
- All relational tables (`duties`, `days`, `dips`, `credit_sales`, `pay_rates`, `pay_items`, `users`, `audit`) are unscoped by tenant.

### Future Multi-Pump Migration Roadmap
If multi-tenancy / multi-outlet management is required in the future:
1. **Schema Extension**: Add a `pump_id TEXT NOT NULL REFERENCES pumps(id)` column (or integer foreign key) to all domain tables: `users`, `duties`, `days`, `day_checks`, `dips`, `credit_sales`, `audit`, `licences`, `atg_readings`, `pay_rates`, `pay_items`, `duty_expenses`, and `shop_sales`.
2. **State Partitioning**: Change the `state` table to key by `(pump_id, id)`.
3. **Compound Uniqueness Constraints**: Update constraints such as `unique(tank_id, bd)` in ATG readings or `primary key(d, mode)` in `day_checks` to include `pump_id`.
4. **Session Context**: Extend session tokens to bind to an active `pump_id` or allow multi-pump owners to switch station context via an `X-Pump-ID` header.
5. **Authorization Middleware**: Update `need()` to enforce row-level tenant filtering (`where pump_id = ?`) across every database query.

## Duty flow

1. **Owner, one time: Pump setup.** Add nozzles (fuel, tank, active or inactive), each nozzle's opening reading for its first duty, fuel rates with a start date, expense categories, and payment modes (turn off the ones you do not use). Credit customers can be made inactive here too.
2. **Manager: Duty tab, Assign duty.** Pick the worker, shift and nozzles. A nozzle already with another worker is locked until that duty is closed. The opening reading is filled from the nozzle's last closing and the rate from the fuel rate table.
3. **Worker:** opens the assigned duty and enters closing readings and testing litres, any lube or shop items sold (picked from Stock), expenses paid from the till, and the money collected by payment mode. Opening and rate are locked. Credit sales saved during the duty are counted automatically. The screen shows expected collection and whether it is short, in excess, or tallies, then the worker submits.
4. **Manager:** reviews the submitted duty, corrects anything, and closes it. Closing a duty reduces lube and shop stock. Then **Close day** when all duties are closed.
5. **Owner:** **Approve day** (or reopen it). The **Day report** shows a summary and a worker-wise detail, for closed duties only. Print it from there.

Expected collection = fuel sales + lube and shop sales, minus credit sales, minus expenses paid from the till. The business day runs from 6 AM to 6 AM, so a night shift past midnight belongs to the previous day.

## Tank stock and dip readings

1. Owner or manager: **Tanks** tab, then **Tanks setup**. Add each tank with its capacity and, optionally, its dip chart (one line per reading, as `dip, litres`). Then, in **Duty**, edit each nozzle and link it to its tank.
2. **Fuel delivery** records a tanker: bill number, and for each tank (up to 3) the litres and the bill amount for that fuel. The total is added to the oil company account in Suppliers automatically. The per-fuel amounts give the cost per litre used in the margin report.
3. **Add dip reading** (managers) or the **Tank dip** tab (workers) records a dip, either as litres or as a dip converted through the tank's chart.
4. Each new dip is checked against the previous one: opening dip + deliveries in between, minus fuel sold on that tank's nozzles (from submitted duties), equals the expected stock. The difference is shown in red when it is more than 0.5% of the fuel sold (and at least 5 L).

## Worker salary

Workers are paid per duty. In the owner-only **Salary** tab:

1. **Set rates** for each worker and shift (Morning, Evening, Night).
2. Each month shows closed duties × rate, plus **bonus**, minus **advances** and **cash shortages** from those duties.
3. **Waive shortage** removes some or all of the shortage deduction. **Record payment** reduces the balance still to pay.
4. Duties still open or waiting for the manager to close are not counted until they are closed.
5. Each worker can see their own month under **My pay**. Managers cannot see the Salary tab.

## Daily summary on WhatsApp

In the **Duty** tab, pick a date and tap **Daily summary**. It builds a message with fuel sold by fuel, collections and shortages, credit sales and total outstanding, tank stock and low-stock items. Tap **Open WhatsApp** and the message is ready to send (to the owner's number by default, or any number you type). You press send yourself. Sending it automatically each night needs the official WhatsApp Business API from Meta and is not included yet.

## Payment reminders

On the **Ledger** tab, tap **Send reminders to everyone with dues**. You see every customer who owes money (largest first) and an editable message. WhatsApp can only open one chat at a time, so tap **Send** beside each customer, or **Open next** to go down the list. Each customer shows when they were last reminded.

## Excel and PDF export

**Excel** and **PDF** buttons are on four screens:

- **Day report** (Duty tab): the summary or the worker-wise detail, whichever you are viewing.
- **Reports** tab: profit and loss, GST, expenses by category, customer outstanding and stock valuation (one Excel sheet each).
- **Customer ledger**: the customer's statement for the date range you picked, with a balance brought forward and ageing.
- **Salary** (owner): the month's pay for every worker, plus the pay entries.

The files are built on your phone or computer, so nothing is sent anywhere. PDFs use a plain fixed-width layout and show the rupee sign as "Rs.".

On a customer, **Send PDF on WhatsApp** opens your phone's share sheet with the PDF attached; pick WhatsApp and then the customer's chat. (WhatsApp does not let an app choose the chat for you.) If your browser cannot share files, the PDF is saved and WhatsApp opens with a short message, and you attach the PDF yourself.

## Vehicle-wise credit report

On the **Ledger** tab, tap **Vehicle-wise credit report**. Pick a month and, if you like, one customer. It shows:

- **Per vehicle:** fills, litres, amount, average and largest fill, how many were flagged, and who served it.
- **Served by:** each vehicle broken down by worker.
- **Monthly litres per vehicle:** the last six months.
- **Unusual fill-ups:** with the reason. A fill is flagged when it is above the vehicle's tank size, or, if no tank size is entered, more than twice that vehicle's average (after at least 3 earlier fills). Fills with no vehicle number, or a vehicle not on the customer's list, are flagged too.

It uses credit sales that workers save, so the worker's credit sale form now has a **Fuel** and **Litres** field. Add each customer's vehicles one per line in the customer form, with the tank size in litres after a comma if you know it (for example `MH12 AB 1234, 200`). Manual ledger entries have no vehicle or litres, so they are not included. Excel and PDF buttons are on this report too.

## Shortage report

In the **Duty** tab, tap **Shortage report**. Pick the period, how many shortages in a month count as "repeat" (3 by default), and whether the trend is by week or month. It shows, for closed duties only:

- **Shortages per worker:** duties, times short, total short, average short, excess and net difference.
- **Repeat shortages:** workers with that many shortages in a single month.
- **Shortage as a percentage of sales:** and the share of their duties that were short.
- **Trend by week or month:** with a column for each worker.

A duty counts as short when the money handed in is ₹1 or more below what was expected. Excel and PDF buttons are on this report too.

## Book, bank deposits and profit margin

- **Duty money in the Book:** when the manager closes a business day, the money handed in by the workers appears in the **Book**. Cash goes to the Cash account, UPI to UPI / wallet, and card and other payment modes to Bank. Money a worker spent from the till is already deducted from what they hand in.
- **Bank deposits:** in the Book, tap **Bank deposit** (date, amount, slip number, deposited by). It moves cash from Cash to Bank. The Book shows **Cash waiting to be banked**, the oldest unbanked day, and a table of recent days with cash handed in, banked and still to bank. Deposits are matched to the oldest days first.
- **Reports tab:** the profit and loss now includes fuel sales and lube and shop sales from closed days, and duty expenses are included in expenses by category. Shop sales recorded in Stock are added to lube and shop sales.
- **Profit and margin:** the Reports tab also shows fuel margin per fuel (sales less the cost of the litres sold, from your delivery bills), shop sales margin (from each item's purchase price), and a net profit before worker pay. Cost per litre is the average of the deliveries in the period, or the latest earlier delivery. A fuel with no delivery cost shows "no cost" and is left out of the profit.

The business date (the 6 AM to 6 AM day) comes from the server, so every phone agrees on the day.

## Fuel products and density checks

**Fuel products (Pump setup, Fuel products):** the owner can add, rename or switch off the fuels sold, for example XP95 or CNG. Each has a unit: litre, kg (for example CNG) or kWh (for example EV charging). Renaming a fuel updates your nozzles, tanks and rates. Duty forms, the day report and the daily WhatsApp summary show the right unit, and liquid-fuel litres are totalled separately from kg and kWh. Tanks, dip readings and the tank stock check apply to liquid fuels only.

**Density checks:** both a **fuel delivery** (for each tank) and a **dip reading** (managers on the Tanks tab, workers on the Tank dip tab) can record:
- the density stated on the supplier's invoice (deliveries only),
- the density you measured with the hydrometer,
- the temperature, and
- the density corrected to 15 °C.

The Tanks tab lists recent readings and flags a reading when it is **outside the allowed range** for that fuel, or when the tanker's mix density **differs from the chalan density by more than the tolerance**. The reading at 15 °C is used when it is entered, otherwise the measured one. Set the lowest, highest and tolerance for each fuel under Pump setup, Fuel products. The defaults shown there (for example 720 to 775 kg/m³ for petrol, 820 to 860 kg/m³ for diesel, tolerance 3 kg/m³) are common figures and are only a starting point: confirm them with your oil company's guidelines.

## Shop products and shop sales

- **Categories and GST rates:** each stock item has a category, a GST rate (0, 5, 12, 18 or 28 per cent) and an optional HSN code. Import a list from Excel in the Stock tab, with a preview before anything is saved.
- **Shop sales (manager):** in the Stock tab, tap **Record shop sale**. Choose the items and quantities and the payment mode. The total includes GST, stock goes down, and the money goes into the book of that payment mode. Recent shop sales are listed in the Stock tab.

## Marathi and Hindi for workers

Workers see a language picker (English, Marathi, Hindi) at the top of their screens. Their choice is saved with their login, so it is the same next time and on any phone. The worker screens are translated: Duty (including the details of past duties), Credit sale, Tank dip, My pay, and the messages and confirmations on them.

- Names you enter yourself stay as you typed them: customers, fuels, expense categories, items and nozzles.
- Owner and manager screens are in English.
- The login screen is in English.
- The translations are in one place in `public/index.html` (the `I18N` list near the top of the script), so any wording can be changed there. Please have someone who reads Marathi and Hindi check the wording, in particular the pay and shortage terms.

## Offline mode and installing the app

**Install on a phone:** open your pump's address in Chrome on Android and tap **Install app** (or the browser menu, then Add to Home screen). On an iPhone, open it in Safari, tap Share, then Add to Home Screen. The app opens full screen with its own icon. Installing and offline use need your site to be on HTTPS (step 6 of the Oracle setup).

**Without a signal, a worker can still:**
- open the app and see their assigned duty,
- fill in and save the duty form (it is also saved on the phone every few seconds) and submit it,
- save credit sales and tank dip readings,
- see their last-loaded pay.

Entries made without a signal are kept on the phone and listed under **Waiting to send** at the top of every worker screen, with the time. They are sent automatically, one after another in the order they were made, when the signal returns (and there is a **Send now** button). If the server refuses an entry, for example for an inactive customer, it stays in the list with the reason and the worker can **Discard** it. A duty waiting to be sent can be reopened with **Edit again**.

Each entry carries a one-time key, so if a signal drops just as a request is sent, the retry never creates a second copy.

Good to know:
- The worker must have opened the app once with a signal after logging in, so the duty, customers, fuels and tanks are saved on the phone.
- A credit sale made offline is checked against the customer's credit limit when it arrives. If it is over the limit it goes to the manager for approval, as usual. The date on it is the business day when it is sent.
- Entries wait on the phone. If the worker clears the browser's data or uninstalls the app before they are sent, those entries are lost, so connect before the end of the day.
- Owner and manager screens need a connection.

## Stock and density registers

In the **Registers** tab, pick the fuel and the month. There are two registers in the layout of your sheets:

- **Stock register** (one per fuel, adding up all its tanks): opening stock, receipts, total stock, sales by meter, pump test, net sales by meter, cumulative sale, sales by dip, daily and cumulative variations.
- **Density register** (one per fuel): the morning density of the main tank with its temperature and the density at 15 °C; each tanker receipt with the density of each compartment, the mix (the simple average of the compartments), the chalan density, the difference, the stock before receipt, the density at 15 °C after decantation, the receipt in KL and the chalan number.

**How figures are taken:**
- **Sales by meter** come from closed duties (closing minus opening reading, less testing litres). Nothing is typed in.
- **Receipts** come from fuel deliveries.
- **Dips:** when recording a dip, choose its purpose: Morning, Before receipt, After receipt or Closing. The app totals the dips of all the fuel's tanks for each purpose. Sales by dip = total stock − closing dip stock.
- **Opening stock** is the previous day's closing. If a day has no closing dip, the next day's opening is carried from the last known closing and sales by dip is left blank for that day, so no figure is invented.
- **Density at 15 °C** is worked out automatically from the measured density and temperature, using the standard petroleum table for gasolines and diesel (API MPMS 11.1). You can also type the 15 °C value if your records already have it.
- **Mix density** of a tanker is the simple average of the compartment densities that were entered.
- The main tank for each fuel is chosen in **Tanks** (tick *Main tank for the density register*). Only that tank's morning density is shown.

The Remarks column is not included. The existing stock check and density list on the Tanks tab are still there. Both registers export to Excel and PDF. Only the owner and manager can see the registers.

The density table uses the standard conversion, which checks out against the sample sheet to within about a third of a kg/m³ on the rows we compared. Your oil company's or the lab's figures remain the reference if they differ.

## Meter register (per nozzle)

The **Meter register** button in the Registers tab shows one line per day, one pair of columns per nozzle: the last pump reading (**Reading**) and the sale since the day before (**Sale**), with the nozzles' names and products. A **Check** column shows, for each day, the difference between the meter sale and the duty figures (closing minus opening, added up). 0 means they agree. Anything else is shown in red so you can find the duty or reading that does not match.

- A nozzle starts from the **opening meter reading set in Pump setup** on the day it was added (the setup date is recorded when the nozzle is created). No history is imported from older sheets.
- On a day with no duty on a nozzle, the reading stays the same and the sale is 0.
- **Sales by meter in the stock register** come from this register, and the stock register notes how many days differ from the duty figures.
- **One register for all tanks and products:** every nozzle is listed, grouped by product (for example Petrol MS and Diesel HSD), with a sale total for each product and one Check column for the day. The Fuel choice in the Registers tab does not change this register.
- A product appears as soon as it has a nozzle, even before its tank is set up.

## Look and layout on phone, tablet and desktop

The screens adjust to the device:

- **Phone:** the sections are a strip of tabs at the top that you swipe sideways (the current one is highlighted), with single-column cards. Workers see their four screens as large tiles.
- **Tablet:** the same tab strip, with cards in two columns.
- **Desktop:** the owner and manager get a sidebar with every section, and cards fill three columns beside it. Workers get a centred column.
- **Dark mode** follows the phone or computer setting, or you can keep it on in the app's theme settings.

The buttons and fields are large enough for a finger, and text is never smaller than a readable size on a phone.

## Cash flow register

**Cash flow** tab (owner and manager). The first time, enter the starting date and the cash in hand at 6 AM on that day. After that, each day is worked out automatically:

**Cash in hand = opening + morning + evening + night − bank deposit + credit recovery − expenses**

- **Opening:** the starting cash for the first day, then the cash in hand the day before. A day runs from 6 AM to 6 AM.
- **Morning, evening and night:** the cash each shift handed in (cash only, not UPI or card) from duties the manager has closed. A duty still waiting to be closed is not counted yet.
- **Bank deposit:** a bank deposit entered in the Book (cash moved to the bank).
- **Credit recovery:** customer payments received in cash in the credit ledger.
- **Expenses:** expenses entered in the Book and paid from the Cash account. UPI or bank expenses are not counted here.

The cash in hand at the end of a day is the opening for the next day. A day with no activity carries the cash forward. Change the starting cash at any time with **Change starting cash**; that restarts the register from the new date. Export to Excel and PDF with the buttons on the screen.

## Dashboards by role

Each person sees a **Dashboard** (owner and manager) or **Home** (worker) tab first when they log in.

- **Owner:** today's sales (fuel and lube and shop), money collected by mode, short or excess, duties today (closed, waiting, open), credit outstanding and how many customers are over their limit, credit sales waiting for approval, today's business-day status, cash in hand (from the cash flow), tanks with book stock and whether a dip was taken today, low stock, shortages for the month, a pay shortage table by worker, the sales of the last seven days, and today's sales by product.
- **Manager:** the same operations figures as the owner, including cash in hand from the cash flow and the pay shortage table (each worker's short duties, amount short, amount waived and amount deducted from pay this month).
- **Worker:** their own duty today (shift, nozzles and status), their credit sales today (saved and waiting for approval), their tank dips today, their pay for the month, a shortage status for the month (number of short duties, amount short, amount waived and amount deducted from pay), and their last five duties. Workers see nothing from other staff.

Figures are for today's business day (6 AM to 6 AM). Money the workers save while offline is shown once it has been sent.

## Expenses register

**Expenses** tab (owner and manager). It lists every expense for the month in one register, from two sources:

- **Duty expenses:** what each worker recorded on their duty (category, details, amount), taken from the till. They show the shift and the worker's name, and whether the duty is still waiting for the manager or closed.
- **Manager expenses:** what the manager entered in the Book, with the category and the account it was paid from (Cash, UPI or Bank).

The screen shows the month's total, the split between workers and manager, the daily totals, the totals by category, and every entry. Choose a category to filter everything on the screen. Export to Excel or PDF with the buttons on the screen.

Duty expenses are already taken off the cash that the worker hands in, so they are not counted twice in the cash flow.

## Books: one per payment mode

The **Book** tab keeps a separate book for every payment mode you use (Cash, UPI, Card, and any others you add in Pump setup, such as Fleet card), plus a **Bank** book. Each book shows its own balance and entries:

- Duty collections go to the book of the mode the worker entered them under. Customer payments, shop sales and supplier payments go to the book of the mode they were paid in.
- Expenses, income and transfers are entered against a book. A transfer moves money between two books.
- A bank deposit moves cash from the Cash book to the Bank book.
- Opening balances are set per book. Older entries (recorded as Cash, UPI or Bank) are placed in the matching book automatically.

Choose **All books** to see every movement, or open one book to see its running balance.

## Salary and the Cash book

Salary and advance payments made in cash are recorded in the Cash book as expenses (category Salary), so the Book and the cash flow both show the money going out. Deleting the payment on the Salary screen removes it from the Book too.

## Cash count and payment slips

On the duty form, the **Money collected** boxes open a popup when tapped:

- **Cash:** enter how many notes and coins you counted (₹2,000, ₹500, ₹200, ₹100, ₹50, ₹20, ₹10 and the coins). The total fills the Cash box.
- **UPI, card and other modes:** enter one line per slip, with the slip or reference number and the amount. The total fills that box.

When the worker submits, the notes must add up to the cash collected and the slips must add up to each mode's amount, or the duty is not sent. The manager sees the notes and slips on the duty when reviewing it. Drafts keep the counts too.

## Worker tabs: shop sale, expense, hand-over

- **Shop sale:** next to Credit sale. Items, quantity and payment mode; no approval. Stock goes down and the money goes to that mode's book.
- **Lubes, shop and expenses on the duty:** tap **Add lube or shop items** or **Add expense**. A popup takes several lines and adds them to the duty when you tap Done. Lube and shop prices come from the stock list. Stock goes down when the manager closes the duty. The separate Expense tab has been removed.
- **Nozzles:** a nozzle is free as soon as the worker submits the duty, so the manager can assign it straight away.
- **Hand-over:** on today's submitted duty, **Hand over nozzle** passes the nozzle to another worker, starting from the reading the worker closed at. No approval needed.
- **Send back:** the manager can send a submitted duty back to the worker to correct. The nozzle stays with the same worker, as long as no one else has been given it in the meantime.
- **Cash count:** notes ₹500 to ₹5 are counted one by one; coins are entered as one rupee amount.
- **Slip numbers:** each slip on a duty is numbered automatically (SL-001, SL-002, ...) and restarts on each duty.

## Excess cash

When a worker hands in more cash than the duty expects, the excess is credited to that worker's advance balance. It is used only in the salary calculation: it reduces the advances the worker has taken, and any surplus adds to their pay. It is not paid out separately, and it does not change the Cash book. Short cash still comes off the worker's pay.

## Shift pay

A worker is paid once per shift per day, however many duties they submitted in that shift. Shortages and excess are still counted for every duty.

## Payroll report

The **Pay report** tab (owner and manager) shows the pay for the month, one section per worker. Each section lists every closed duty day by day (shift, nozzles, litres, sales, cash collected, short or excess, duty pay), with advances, bonuses, salary payments and excess credits on the day they were made. A summary at the end gives the net pay and the balance to pay. The owner and manager see every worker. A worker sees only their own report, from the **Monthly report** button on the My pay screen. Export to Excel or PDF with the buttons on the screen.

## Send back and hand-over locks

- The manager can send back any submitted duty to the worker to correct, even when its nozzle has been handed to another worker.
- While a nozzle is handed over, its **closing meter reading** is locked. The worker can still correct everything else (testing litres, cash, slips, expenses, shop items and notes).
- Only the worker corrects a closing reading. The manager cannot change it on a submitted duty; the manager sends the duty back instead.
- To correct a locked closing, the manager cancels the hand-over. The receiving duty is removed (it does not show on the other worker's screen), and the closing unlocks.
- After the worker corrects and resubmits, the manager assigns the nozzle again, and the new opening is the corrected closing.

## 6 AM dip and day sync

- Each tank has exactly one dip per business day: the 6 AM opening dip. A second dip for the same tank on the same day is refused, and a negative dip reading is refused.
- No nozzle can be assigned, handed over or submitted until its tank has today's 6 AM dip.
- The tank book stock counts closed duties only, so a sale counts once the manager has closed its duty.
- The stock and meter registers count a day's sales only after the day is closed. A day's closing figure is the next day's 6 AM dip.
- The 6 AM **Morning reading** is one form for all tanks. Every tank needs its stock reading (litres or dip) and its density with temperature. Tanks already read that day are skipped. Nothing is saved unless every tank is complete. Each tank shows its expected stock (book stock: the last reading plus receipts minus closed sales) so the reading can be checked against it.
- **Stock receipt:** litres, amount, supplier and bill number only.
- **Receipt density:** chalan density, the four compartment densities, and the density after decantation, recorded against the receipt. The density register shows the after-decantation figure; the stock-before-receipt column stays blank.

## ATG stock

The **ATG stock** tab (owner and manager) records the tank-gauge reading for every tank once a day. Each day's book stock is the previous day's ATG reading, plus receipts, minus closed sales. The **daily variation** is the ATG reading minus book stock for that day. The **cumulative variation** adds up the daily variations. The two are shown in separate columns. The registers are unchanged.

## Reconcile the day

The **Reconcile** tab (owner and manager) checks each day's money. For a chosen business day it compares each module's figure with the Book: duty collections, shop sales, credit recovery, supplier payments, manager expenses and bank deposits. It also checks the cash flow's cash in hand against the cash book. A check that matches shows "Matches"; any difference shows as "Check" with the amount. The actual-money checks compare the notes and coins counted on each duty, and the slips, with the money collected, and the day report's collections with the Book. A duty with no cash count is flagged.

## Scope

One database serves one petrol pump. For a second pump, run a separate copy of the app with its own database.

**Credit sale (worker):** tap **Add credit sale**. The popup takes one customer and vehicle, with one line per sale (starts with one, Add line for more). Save all sends every line to the customer ledger. A line over the customer’s available credit is sent to a manager for approval after you confirm.

## Licences (owner)

The **Licences** tab tracks the pump's licences and certificates: name, number, issued date, expiry date, and a scanned copy (PDF or PNG, up to 5 MB). Each licence shows its days left: expired, inside 30 days, inside 90 days, or valid. The four summary tiles count these, and the owner's dashboard shows how many are expired or due within 30 days. Only the owner can see the licences and their copies. Renewing a licence means editing its expiry date.

**Export on every report:** each report has **Excel**, **PDF** and **WhatsApp** buttons. WhatsApp opens the phone’s share sheet with the PDF attached (WhatsApp is in the list). If the phone can’t share files, the PDF is downloaded and WhatsApp opens with a message to attach it.

## Approving the day

Before the owner approves a closed day, every payment mode (cash, UPI, card and any others) must be **counted and ticked**. Tap **Approve day**, enter the amount counted for each mode, and tick it. The expected amount comes from the day’s duties, shop sales and customer payments. If the counted amount differs, a note is required. Approval is refused until every mode is ticked.

## Pump setup (all settings)

All settings are under **Pump setup**, in the order to set them up:

1. Business details
2. Fuel products
3. Payment modes
4. Nozzles
5. Opening readings
6. Fuel rates
7. Expense categories
8. Credit customers
9. Workers (team)
10. Licences
11. Backup
12. Audit log

The owner sees every step. The manager sees only Workers and Licences.

## Daily required

The **Daily required** tab (after Duty) is a checklist of what must be done today. Owner and manager see the morning readings, density and ATG for every tank, duties assigned and closed, the day closed and approved, collections verified, credit approvals, and licences due. Workers see whether their duty has started and been submitted. Each item shows a tick or a cross, with the missing tanks or duties named.

**Manager review of a duty:** the manager cannot change any figure on a duty. The manager can **Close duty** as it stands, or **Send back** for the worker to correct. The owner can still edit a duty.

**Worker duty export:** on the duty screen, **Excel**, **PDF** and **WhatsApp** export everything recorded on the duty: the summary, nozzle readings, collections by mode, the cash count, payment slips, lube and shop items, expenses and the note. The day report (owner and manager) has the same three buttons.

**Credit sales on the duty:** each duty's credit sales (customer, fuel, litres, amount, and whether counted or waiting for approval) appear in the day report's worker-wise duty detail, and in the duty export. They do not appear on the duty screen.

**Manager financial summary (day report):** total sales (fuel, lube and shop, shop counter), credit sales given, credit recovered, collections by mode, expenses from the till and by the manager, bank deposits and cash in hand at day end. It is also in the day report export.

## Merged tabs

Related screens are grouped under one tab. A row of sub-tabs sits above the screen:

- **Pay:** Salary (owner), Pay report
- **Cash:** Book, Cash flow
- **Day:** Day report, Reconcile, Expenses
- **Tanks:** Tanks, ATG stock
- **Checks:** Daily required, Licences
- **Reports:** Reports, Registers

Each sub-tab opens the same screen as before. The owner sees every group; the manager sees the groups they can use.

## Theme and screen sizes

- **Theme switcher:** the top bar has a Theme list with Indigo (default) and the six OMC colour sets: IndianOil, BPCL, HPCL, Nayara Energy, Jio-bp and Shell. A saved theme that is no longer in the list falls back to Indigo. The choice is remembered on that device.
- **Screen sizes:** every screen fits a phone, tablet and desktop. The top bar wraps on small screens, buttons wrap, and wide tables scroll sideways inside their own box.

## Printing

- **A4 for every report:** each report has **Print A4**. It prints the same A4 document as the PDF button.
- **Thermal printer for duty reports:** the duty screen has **Thermal print (duty)**, and each duty in the day report has one too. The receipt is 80 mm wide, in a monospace font, and lists the duty's readings, collections, cash count, slips, lube and shop items, expenses and note. It prints on a standard 80 mm receipt printer; for a 58 mm printer, set the paper size to 58 mm in the print dialog.

## OMC colour sets

The theme list includes six oil marketing company (OMC) colour sets: IndianOil, BPCL, HPCL, Nayara Energy, Jio-bp and Shell. Each uses its primary colour for buttons and the active tab, and its secondary colour as an underline on the active tab. The text on buttons and the focus ring switch to black or white so they stay readable. These are colour settings for the app only. They are not official paint or signage specifications for any petrol station.

## Multi-station

Each station has its own database file in `stations/` (listed in `registry.db`) and its own backup folder. Every request is sent to one station only, so one station cannot see another's data or backups.

- **Turn it on** with `SIGNUP_ENABLED=1`. The app then asks for a station address, or lets a new station register. Use this on a fresh deployment: in this mode the single-station `data.db` is not used.
- **Choosing a station:** by address, on one shared domain. Staff can use the link `https://your-domain/?station=<address>`. The owner gets it from the **Staff link** button in the top bar and can share it on WhatsApp.
- **Registering a station:** station name, a unique station address (3 to 30 letters, digits or hyphens), the owner's name, mobile and password, and consent to the privacy notice.
- **Owner's data rights** (Pump setup, Backup step): **Export all data** (JSON) and **Delete my station**, which closes the station straight away and records the request.
- **Backups:** the nightly backup covers every active station and keeps 30 per station. Restore only works inside the station.
- **Settings:** `SIGNUP_ENABLED`, `DATA_DIR` (registry and station databases), `PRIVACY_CONTACT` (shown in the privacy notice), `BASE_DOMAIN` (optional sub-domain mode, not needed for the shared address), `BACKUP_ANYTIME` (testing only).
- **Privacy notice:** the text in the app is a draft. Have a lawyer review it, and set `PRIVACY_CONTACT`, before you launch.
- **Not built yet:** mobile verification, sign-up rate limits, encryption of the database files, deleting a closed station's data after the retention period, and billing.

## Super admin (platform operator)

The super admin is for the person who runs the service. It is separate from every station login.

- **Create the first one on the server:** `node create-admin.js` (or `npm run create-admin`). It asks for a name, a mobile number and a password (10 or more characters, with a letter and a digit; what you type is not shown). If you set `DATA_DIR` for the server, set the same value when you run it. It can only be created this way, never from a web page, so nobody can claim it by finding the page first.
- **Log in** at `https://your-domain/admin`. The login has its own cookie or Bearer token, which is only sent to the admin routes. A session lasts 8 hours, and 5 wrong tries lock that mobile number for 15 minutes.
- **What an admin can do:** see every station (name, address, status, owner mobile, when the privacy notice was accepted, size of the data file); suspend or reactivate a station, with a reason that is logged; add or remove other admins (their own password is needed); change their own password (their other devices are logged out); and read the last 100 admin actions.
- **What an admin cannot do:** open a station's business data. No admin route touches a station database, and there is no way to log in as a station user. A station that has asked to be deleted cannot be reactivated by an admin.
- **If every admin password is lost,** run `node create-admin.js` again on the server to create a new admin.

## Try it on your computer

```bash
npm install
node server.js
# open http://127.0.0.1:3000 and create the owner account
```

## Put it on Oracle Cloud (Always Free VM)

1. **Create the VM.** Ubuntu 22.04 or 24.04. Note its public IP.
2. **Open web ports.** In the VM's subnet security list, allow ingress TCP 80 and 443. Then on the VM:
   ```bash
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   ```
3. **Install Node 22.**
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```
4. **Copy this folder** to `/opt/petrol-app` (for example with `scp -r`), then:
   ```bash
   cd /opt/petrol-app && npm install --omit=dev
   ```
   The project already includes a ready-made SQLite engine for both Intel and ARM (Ampere) servers, and a `.npmrc` file that stops npm from trying to compile anything, so you do not need build tools. It needs Node 22 or newer. Copy the hidden `.npmrc` file too (`scp -r` and zip both include it).
5. **Run it as a service.** Create `/etc/systemd/system/petrol.service`:
   ```ini
   [Unit]
   Description=Petrol pump server
   After=network.target

   [Service]
   WorkingDirectory=/opt/petrol-app
   ExecStart=/usr/bin/node server.js
   Environment=PORT=3000
   Restart=always
   User=ubuntu

   [Install]
   WantedBy=multi-user.target
   ```
   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now petrol
   ```
6. **Add HTTPS (required).** Logins send passwords, so never use plain HTTP. You need a domain name (a free one from duckdns.org works) pointing at the VM's IP. Then:
   ```bash
   sudo apt-get install -y caddy
   ```
   Put this in `/etc/caddy/Caddyfile` and run `sudo systemctl reload caddy`:
   ```
   yourname.duckdns.org {
       reverse_proxy 127.0.0.1:3000
   }
   ```
7. **Open your address** in a browser, create the owner account, then add managers and workers in the Team tab. On phones, use "Add to Home screen".

## Backups (do this)

The server now saves a full copy of the database every night after 2 AM into the `backups` folder (the latest 30 are kept). The owner sees them in the **Backup** tab: **Back up now**, **Download**, and **Restore**. A restore first saves a safety copy of the current data, replaces everything with the chosen backup, and logs everyone out.

Still copy the backups off the VM now and then (your computer or Google Drive), because a backup on the same machine does not protect you if the machine is lost. You can also copy the database file itself:

```bash
sudo apt-get install -y sqlite3
sqlite3 /opt/petrol-app/data.db ".backup ~/data-$(date +%F).db"
```

## Audit log

The owner sees **Pump setup, then Audit log**: every change with who made it and when. It covers edits to customers, shop sales, stock, suppliers, rates and other business data (for example "Customers changed: Shree (entries 3 to 4)"), plus duty assignment, closing, reopening and corrections (with the before and after figures), day close and approval, credit approvals, pay entries, dips, user changes, logins, backups and restores.

## Good to know

- Business data is stored in separate sections (customers, shop sales, stock, suppliers, book, business details, tanks, setup). Two people only clash if they change the same section at the same moment, and then the second person is told which section and asked to reload.
- Worker credit sales are separate again, so they never clash.
- After 5 wrong passwords, that mobile number is locked for 15 minutes.
- Forgot the owner password? Stop the server, then run:
  ```bash
  node -e "const D=require('better-sqlite3'),b=require('bcryptjs');new D('data.db').prepare('update users set hash=? where role=\'owner\'').run(b.hashSync('NewPass123',10))"
  ```
  and log in with `NewPass123`, then change it.
