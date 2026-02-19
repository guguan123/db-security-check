<?php
/*
Plugin Name: MySQL Security Monitor
Description: 监控数据库是否有异常
Version: 1.3
Author: GuGuan123's Cat
*/

if (!defined('ABSPATH')) exit;

class GG_DB_Security_Monitor {

	private $option_name = 'gg_db_monitor_settings';
	private $result_option_name = 'gg_db_monitor_result';

	public function __construct() {
		add_action('admin_menu', array($this, 'create_menu'));
		add_action('gg_db_weekly_check_event', array($this, 'run_security_check_cron'));
		
		// 激活与停用
		register_activation_hook(__FILE__, array($this, 'activate'));
		register_deactivation_hook(__FILE__, array($this, 'deactivate'));
		register_uninstall_hook(__FILE__, array($this, 'uninstall'));
	}

	/**
	 * 核心检测逻辑
	 * @return array 检测结果数组
	 */
	public function run_security_check() {
		global $wpdb;
		$alerts = [];
		$settings = get_option($this->option_name);

		// 检测 --skip-grant-tables
		$result = $wpdb->get_row("SHOW VARIABLES LIKE 'skip_grant_tables'");
		if ($result && strtoupper($result->Value) == 'ON') {
			$alerts[] = "🚨 危险：数据库正处于 --skip-grant-tables 模式运行！";
		}

		// 获取白名单，如果没有则取默认值
		$allowed_db = isset($settings['allowed_databases']) ? $settings['allowed_databases'] : array('guguan_sql', 'information_schema', 'performance_schema', 'mysql', 'sys');

		// 检测异常数据库
		$unknown_dbs = array_diff($wpdb->get_col("SHOW DATABASES"), $allowed_db);

		if (!empty($unknown_dbs)) $alerts[] = "🔍 检测到异常数据库：" . implode(', ', $unknown_dbs);

		return $alerts;
	}

	public function run_security_check_cron() {
		$alerts = $this->run_security_check(true);
		if (!empty($alerts)) {
			$settings = get_option($this->option_name);
			if (!empty($settings['email_notify'])) {
				$to = get_option('admin_email');
				$subject = get_bloginfo('name') . ' - 数据库异常警报';
				$body = implode(PHP_EOL, $alerts);
				wp_mail($to, $subject, $body);
			}
		}
		update_option($this->result_option_name, array('time' => current_time('Y-m-d H:i:s'), 'result' => $alerts));
	}

	// 创建管理页面
	public function create_menu() {
		add_options_page('DB Security', 'DB Security', 'manage_options', 'gg-db-monitor', array($this, 'settings_page'));
	}

	public function settings_page() {
		global $wpdb;
		
		// 保存设置
		if (isset($_POST['save_settings'])) {
			// 将逗号或换行分隔的字符串转为数组
			$db_input = str_replace(array("\r", "\n"), ',', $_POST['allowed_databases']);
			$db_array = array_filter(array_map('trim', explode(',', $db_input)));
			
			$new_settings = array(
				'email_notify' => isset($_POST['email_notify']) ? 1 : 0,
				'allowed_databases' => array_values(array_unique($db_array))
			);
			update_option($this->option_name, $new_settings);
			echo '<div class="updated"><p>设置已保存喵！</p></div>';
		}

		$settings = get_option($this->option_name);

		// 每次打开页面都自动运行检测
		$alerts = $this->run_security_check(false);
		$current_db_list = implode("\n", $settings['allowed_databases'] ?? []);

		?>
		<div class="wrap">
			<h1>🔒 MySQL Security Monitor</h1>
			<p>当前数据库：<strong><?php echo $wpdb->dbname; ?></strong></p>
			<hr>

			<h3>检测结果：</h3>
			<?php if (empty($alerts)): ?>
				<div class="notice notice-success"><p><strong>✅ 数据库状态良好</strong></p></div>
			<?php else: ?>
				<div class="notice notice-error">
					<p><strong>⚠️ 发现安全隐患：</strong></p>
					<ul><?php foreach ($alerts as $alert) echo "<li>".esc_html($alert)."</li>"; ?></ul>
				</div>
			<?php endif; ?>

			<form method="post" style="margin-top: 20px; background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
				<h3>⚙️ 设置中心</h3>
				<table class="form-table">
					<tr>
						<th scope="row">邮件预警</th>
						<td>
							<input type="checkbox" name="email_notify" <?php checked(1, $settings['email_notify'] ?? 0); ?>> 开启自动通知
						</td>
					</tr>
					<tr>
						<th scope="row">数据库白名单</th>
						<td>
							<textarea name="allowed_databases" rows="5" class="large-text" placeholder="每行一个数据库名称"><?php echo esc_textarea($current_db_list); ?></textarea>
							<p class="description">在此列出的数据库不会触发警报：<strong><?php echo $wpdb->dbname; ?></strong></p>
						</td>
					</tr>
				</table>
				<?php submit_button('保存设置', 'primary', 'save_settings'); ?>
			</form>
		</div>
		<?php
	}

	// 后台顶部提醒 - 每次加载后台页面都会检测（或许以后会用上？）
	public function display_admin_alerts() {
		// 只在非设置页面显示提醒（避免重复显示）
		if (isset($_GET['page']) && $_GET['page'] === 'gg-db-monitor') return;


		// 获取检测报告
		$check_result = get_option($this->result_option_name);

		if (!empty($check_result['result'])) {
			echo '<div class="notice notice-error is-dismissible">';
			echo '<p><strong>🚨 数据库安全警告！</strong> 发现 ' . count($check_result['result']) . ' 个问题，请<a href="' . admin_url('options-general.php?page=gg-db-monitor') . '">立即查看详情</a>。</p>';
			echo '</div>';
		}
	}

	// 激活插件：自动探测并记录
	public function activate() {
		global $wpdb;
		
		// 初始化白名单
		$settings = get_option($this->option_name);
		if (!$settings) {
			// 获取当前库名 + 系统库名
			$default_allowed = array(
				$wpdb->dbname,
				'information_schema',
				'performance_schema',
				'mysql',
				'sys'
			);
			update_option($this->option_name, array(
				'email_notify' => 1,
				'allowed_databases' => $default_allowed
			));
		}

		// 注册 Cron
		if (!wp_next_scheduled('gg_db_weekly_check_event')) {
			wp_schedule_event(time(), 'weekly', 'gg_db_weekly_check_event');
		}
	}

	public function deactivate() {
		wp_clear_scheduled_hook('gg_db_weekly_check_event');
	}

	public function uninstall() {
		delete_option($this->option_name);
		delete_option($this->result_option_name);
	}
}

new GG_DB_Security_Monitor();
